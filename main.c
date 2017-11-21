/*
 * Copyright (c) 2011-2013 Luc Verhaegen <libv@skynet.be>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sub license,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <dlfcn.h>

#define u32 uint32_t
#define s32 int32_t
#define u64 uint64_t
#define s64 int64_t

#include "mali/mali_utgard_uk_types.h"
#include "mali/mali_utgard_ioctl.h"

static int mali_address_add(void *address, unsigned int size, unsigned int physical);
static int mali_address_remove(void *address, int size);
static int ump_id_add(unsigned int id, unsigned int size, void *address);
static int ump_physical_add(unsigned int id, unsigned int physical);
static int mali_ioctl(int request, void *data);
static int mali_external_add(void *address, unsigned int physical,
			     unsigned int size, unsigned int cookie);
static int mali_external_remove(unsigned int cookie);
static void mali_memory_dump(void);
static void mali_mmu_dump(void *ctx);

static pthread_mutex_t serializer[1] = { PTHREAD_MUTEX_INITIALIZER };

static int mali_version;

static inline void
serialized_start(const char *func)
{
	pthread_mutex_lock(serializer);
}

static inline void
serialized_stop(void)
{
	pthread_mutex_unlock(serializer);
}

/*
 *
 * Basic log writing infrastructure.
 *
 */
FILE *lima_wrap_log = NULL;
int frame_count = 0;

void
lima_wrap_log_open(void)
{
	char *filename;
	char buffer[1024];

	if (lima_wrap_log)
		return;

	filename = getenv("LIMA_WRAP_LOG");
	if (!filename)
		filename = "/home/yuq/log/log";

	snprintf(buffer, sizeof(buffer), "%s.%04d", filename, frame_count);

	lima_wrap_log = fopen(buffer, "w");
	if (!lima_wrap_log) {
		printf("Error: failed to open wrap log %s: %s\n", filename,
		       strerror(errno));
		lima_wrap_log = stdout;
	}
}

int
wrap_log(const char *format, ...)
{
	va_list args;
	int ret;

	lima_wrap_log_open();

	va_start(args, format);
	ret = vfprintf(lima_wrap_log, format, args);
	va_end(args);

	return ret;
}

void
lima_wrap_log_next(void)
{
	if (lima_wrap_log) {
		fclose(lima_wrap_log);
		lima_wrap_log = NULL;
	}

	frame_count++;

	lima_wrap_log_open();
}

/*
 * Wrap around the libc calls that are crucial for capturing our
 * command stream, namely, open, ioctl, and mmap.
 */
static void *libc_dl;

static int
libc_dlopen(void)
{
	libc_dl = dlopen("libc.so.6", RTLD_LAZY);
	if (!libc_dl) {
		printf("Failed to dlopen %s: %s\n",
		       "libc.so", dlerror());
		exit(-1);
	}

	return 0;
}

static void *
libc_dlsym(const char *name)
{
	void *func;

	if (!libc_dl)
		libc_dlopen();

	func = dlsym(libc_dl, name);

	if (!func) {
		printf("Failed to find %s in %s: %s\n",
		       name, "libc.so", dlerror());
		exit(-1);
	}

	return func;
}

static int dev_mali_fd;
static int dev_ump_fd;
static int dev_drm_fd;

/*
 *
 */
static int (*orig_open)(const char* path, int mode, ...)  = NULL;

int
open(const char* path, int flags, ...)
{
	mode_t mode = 0;
	int ret;
	int mali = 0;
	int ump = 0;
	int drm = 0;

	if (!strcmp(path, "/dev/mali")) {
		mali = 1;
		serialized_start(__func__);
	} else if (!strcmp(path, "/dev/ump")) {
		ump = 1;
	    	serialized_start(__func__);
	} else if (!strcmp(path, "/dev/dri/card0")) {
		drm = 1;
	}

	if (!orig_open)
		orig_open = libc_dlsym(__func__);

	if (flags & O_CREAT) {
		va_list  args;

		va_start(args, flags);
		mode = (mode_t) va_arg(args, int);
		va_end(args);

		ret = orig_open(path, flags, mode);
	} else {
		ret = orig_open(path, flags);

		if (ret != -1) {
			if (mali)
				dev_mali_fd = ret;
			else if (ump)
				dev_ump_fd = ret;
			else if (drm)
				dev_drm_fd = ret;
		}
	}

	if (mali || ump)
		serialized_stop();

	return ret;
}

/*
 *
 */
static int (*orig_close)(int fd) = NULL;

int
close(int fd)
{
	int ret;

	if (fd == dev_mali_fd)
	    	serialized_start(__func__);

	if (!orig_close)
		orig_close = libc_dlsym(__func__);

	if (fd == dev_mali_fd) {
		wrap_log("/* CLOSE */");
		dev_mali_fd = -1;
	}

	ret = orig_close(fd);

	if (fd == dev_mali_fd)
		serialized_stop();

	return ret;
}

static int (*orig_ioctl)(int fd, unsigned long request, ...) = NULL;

int ioctl(int fd, unsigned long request, ...)
{
	int ioc_size = _IOC_SIZE(request);
	int ret;
	int yield = 0;

	serialized_start(__func__);

	if (!orig_ioctl)
		orig_ioctl = libc_dlsym(__func__);

	if (ioc_size) {
		va_list args;
		void *ptr;

		va_start(args, request);
		ptr = va_arg(args, void *);
		va_end(args);

		if (fd == dev_mali_fd) {
			if (request == MALI_IOC_WAIT_FOR_NOTIFICATION)
				yield = 1;

			ret = mali_ioctl(request, ptr);
		} else
			ret = orig_ioctl(fd, request, ptr);
	} else {
		if (fd == dev_mali_fd)
			ret = mali_ioctl(request, NULL);
		else
			ret = orig_ioctl(fd, request);
	}

	serialized_stop();

	if (yield)
		sched_yield();

	return ret;
}

/*
 *
 */
void *(*orig_mmap)(void *addr, size_t length, int prot,
		   int flags, int fd, off_t offset) = NULL;

void *
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *ret;

	serialized_start(__func__);

	if (!orig_mmap)
		orig_mmap = libc_dlsym(__func__);

	ret = orig_mmap(addr, length, prot, flags, fd, offset);

	if (fd == dev_mali_fd) {
		wrap_log("/* MMAP 0x%08lx (0x%08x) = %p */\n\n", offset, length, ret);
		mali_address_add(ret, length, offset);
		memset(ret, 0, length);
	} else if (fd == dev_ump_fd)
		ump_id_add(offset >> 12, length, ret);

	serialized_stop();

	return ret;
}

/*
 *
 */
int (*orig_munmap)(void *addr, size_t length) = NULL;

int
munmap(void *addr, size_t length)
{
	int ret;

	serialized_start(__func__);

	if (!orig_munmap)
		orig_munmap = libc_dlsym(__func__);

	ret = orig_munmap(addr, length);

	if (!mali_address_remove(addr, length))
		wrap_log("/* MUNMAP %p (0x%08x) */\n\n", addr, length);

	serialized_stop();

	return ret;
}

int (*orig_fflush)(FILE *stream) = NULL;

int
fflush(FILE *stream)
{
	int ret;

	serialized_start(__func__);

	if (!orig_fflush)
		orig_fflush = libc_dlsym(__func__);

	ret = orig_fflush(stream);

	if (stream != lima_wrap_log)
		orig_fflush(lima_wrap_log);

	serialized_stop();

	return ret;
}

/*
 *
 * Now the mali specific ioctl parsing.
 *
 */
char *
ioctl_dir_string(int request)
{
	switch (_IOC_DIR(request)) {
	default: /* cannot happen */
	case 0x00:
		return "_IO";
	case 0x01:
		return "_IOW";
	case 0x02:
		return "_IOR";
	case 0x03:
		return "_IOWR";
	}
}

static void
dev_mali_get_api_version_pre(void *data)
{
	_mali_uk_get_api_version_s *version = data;

	wrap_log("/* IOCTL MALI_IOC_GET_API_VERSION IN */\n");

	wrap_log("#if 0 /* API Version */\n\n");

	wrap_log("_mali_uk_get_api_version_s mali_version_in = {\n");
	wrap_log("\t.version = 0x%08x,\n", version->version);
	wrap_log("};\n\n");

	wrap_log("#endif /* API Version */\n\n");
}

static void
dev_mali_get_api_version_post(void *data, int ret)
{
	_mali_uk_get_api_version_s *version = data;

	wrap_log("/* IOCTL MALI_IOC_GET_API_VERSION OUT */\n");

	wrap_log("#if 0 /* API Version */\n\n");

	wrap_log("_mali_uk_get_api_version_s mali_version_out = {\n");
	wrap_log("\t.version = 0x%08x,\n", version->version);
	wrap_log("\t.compatible = %d,\n", version->compatible);
	wrap_log("};\n\n");

	wrap_log("#endif /* API Version */\n\n");

	mali_version = version->version & 0xFFFF;

	printf("Mali version: %d\n", mali_version);
}

static void
dev_mali_memory_attach_ump_mem_post(void *data, int ret)
{
	_mali_uk_attach_ump_mem_s *ump = data;

	ump_physical_add(ump->secure_id, ump->mali_address);
}

static void
dev_mali_memory_map_ext_mem_post(void *data, int ret)
{
	_mali_uk_map_external_mem_s *ext = data;

	printf("map_ext_mem: ctx %p, phys_addr 0x%08X, size 0x%08X, address 0x%08X, rights 0x%08X, flags 0x%08X, cookie 0x%08X\n",
	       ext->ctx, ext->phys_addr, ext->size, ext->mali_address, ext->rights, ext->flags, ext->cookie);

	if (!ret)
		mali_external_add((void *)ext->mali_address, ext->phys_addr,
				  ext->size, ext->cookie);
}

static void
dev_mali_memory_unmap_ext_mem_post(void *data, int ret)
{
	_mali_uk_map_external_mem_s *ext = data;

	printf("unmap_ext_mem: ctx %p, cookie 0x%08X\n",
	       ext->ctx, ext->cookie);

	mali_external_remove(ext->cookie);
}

static void
dev_mali_pp_number_of_cores_post(void *data, int ret)
{
	_mali_uk_get_pp_number_of_cores_s *number = data;

	wrap_log("/* IOCTL MALI_IOC_PP_NUMBER_OF_CORES_GET OUT */\n");

	wrap_log("#if 0 /* PP Number Of Cores */\n\n");

	wrap_log("_mali_uk_get_pp_number_of_cores_s mali_pp_number_of_cores = {\n");
	wrap_log("\t.number_of_total_cores = %d,\n", number->number_of_total_cores);
	wrap_log("\t.number_of_enabled_cores = %d,\n", number->number_of_enabled_cores);
	wrap_log("};\n\n");

	wrap_log("#endif /* PP Number Of Cores */\n\n");
}

static void
dev_mali_gp_number_of_cores_post(void *data, int ret)
{
	_mali_uk_get_gp_number_of_cores_s *number = data;

	wrap_log("/* IOCTL MALI_IOC_GP_NUMBER_OF_CORES_GET OUT */\n");

	wrap_log("#if 0 /* GP Number Of Cores */\n\n");

	wrap_log("_mali_uk_get_gp_number_of_cores_s mali_gp_number_of_cores = {\n");
	wrap_log("\t.number_of_cores = %d,\n", number->number_of_cores);
	wrap_log("};\n\n");

	wrap_log("#endif /* GP Number Of Cores */\n\n");
}

static void
dev_mali_pp_core_version_post(void *data, int ret)
{
	_mali_uk_get_pp_core_version_s *version = data;

	wrap_log("/* IOCTL MALI_IOC_PP_CORE_VERSION_GET OUT */\n");

	wrap_log("#if 0 /* PP Core Version */\n\n");

	wrap_log("_mali_uk_get_pp_core_version_s mali_pp_version = {\n");
	wrap_log("\t.version = 0x%x,\n", version->version);
	wrap_log("};\n\n");

	wrap_log("#endif /* PP Core Version */\n\n");
}

static void
dev_mali_gp_core_version_post(void *data, int ret)
{
	_mali_uk_get_gp_core_version_s *version = data;

	wrap_log("/* IOCTL MALI_IOC_GP_CORE_VERSION_GET OUT */\n");

	wrap_log("#if 0 /* GP Core Version */\n\n");

	wrap_log("_mali_uk_get_gp_core_version_s mali_gp_version = {\n");
	wrap_log("\t.version = 0x%x,\n", version->version);
	wrap_log("};\n\n");

	wrap_log("#endif /* GP Core Version */\n\n");
}

static void
dev_mali_wait_for_notification_pre(void *data)
{
	_mali_uk_wait_for_notification_s *notification = data;

	wrap_log("/* IOCTL MALI_IOC_WAIT_FOR_NOTIFICATION IN */\n");

	wrap_log("#if 0 /* Notification */\n\n");

	wrap_log("_mali_uk_wait_for_notification_s mali_notification_in = {\n");
	wrap_log("};\n\n");

	wrap_log("#endif /* Notification */\n\n");

	/* some kernels wait forever otherwise */
	serialized_stop();
}

/*
 * At this point, we do not care about the performance counters.
 */
static void
dev_mali_wait_for_notification_post(void *data, int ret)
{
	_mali_uk_wait_for_notification_s *notification = data;

	/* to match the pre function */
	serialized_start(__func__);

	wrap_log("/* IOCTL MALI_IOC_WAIT_FOR_NOTIFICATION OUT */\n");

	wrap_log("#if 0 /* Notification */\n\n");

	wrap_log("_mali_uk_wait_for_notification_s wait_for_notification = {\n");
	wrap_log("\t.code.type = 0x%x,\n", notification->type);

	switch (notification->type) {
	case _MALI_NOTIFICATION_GP_FINISHED:
		{
			_mali_uk_gp_job_finished_s *info =
				&notification->data.gp_job_finished;

			wrap_log("\t.data.gp_job_finished = {\n");

			wrap_log("\t\t.user_job_ptr = 0x%x,\n", info->user_job_ptr);
			wrap_log("\t\t.status = 0x%x,\n", info->status);
			wrap_log("\t\t.heap_current_addr = 0x%x,\n",
				 info->heap_current_addr);

			wrap_log("\t},\n");

			//mali_memory_dump();
		}
		break;
	case _MALI_NOTIFICATION_PP_FINISHED:
		{
			_mali_uk_pp_job_finished_s *info =
				&notification->data.pp_job_finished;

			wrap_log("\t.data.pp_job_finished = {\n");

			wrap_log("\t\t.user_job_ptr = 0x%x,\n", info->user_job_ptr);
			wrap_log("\t\t.status = 0x%x,\n", info->status);

			wrap_log("\t},\n");

			//mali_memory_dump();
		}
		break;
	case _MALI_NOTIFICATION_GP_STALLED:
		{
			_mali_uk_gp_job_suspended_s *info =
				&notification->data.gp_job_suspended;

			wrap_log("\t.data.gp_job_suspended = {\n");
			wrap_log("\t\t.user_job_ptr = 0x%x,\n", info->user_job_ptr);
			wrap_log("\t\t.cookie = 0x%x,\n", info->cookie);
			wrap_log("\t},\n");
		}
		break;
	default:
		wrap_log("};\n\n");
		break;
	}

	wrap_log("};\n\n");
	wrap_log("#endif /* Notification */\n\n");

	/* some post-processing */
	if (notification->type == _MALI_NOTIFICATION_PP_FINISHED) {
		printf("Finished frame %d\n", frame_count);
		mali_memory_dump();
		mali_mmu_dump(notification->ctx);

		/* We finished a frame */
		lima_wrap_log_next();
	}
}

struct lima_gp_frame_registers {
	unsigned int vs_commands_start;
	unsigned int vs_commands_end;
	unsigned int plbu_commands_start;
	unsigned int plbu_commands_end;
	unsigned int tile_heap_start;
	unsigned int tile_heap_end;
};

static void
dev_mali_gp_job_start_pre(void *data)
{
	_mali_uk_gp_start_job_s *job = data;
	struct lima_gp_frame_registers *frame = (void *)job->frame_registers;

	wrap_log("/* IOCTL MALI_IOC_GP2_START_JOB IN; */\n");

	wrap_log("_mali_uk_gp_start_job_s gp_job = {\n");

	wrap_log("\t.ctx = 0x%x,\n", job->ctx);
	wrap_log("\t.user_job_ptr = 0x%x,\n", job->user_job_ptr);
	wrap_log("\t.priority = 0x%x,\n", job->priority);

	wrap_log("\t.frame.vs_commands_start = 0x%x,\n", frame->vs_commands_start);
	wrap_log("\t.frame.vs_commands_end = 0x%x,\n", frame->vs_commands_end);
	wrap_log("\t.frame.plbu_commands_start = 0x%x,\n", frame->plbu_commands_start);
	wrap_log("\t.frame.plbu_commands_end = 0x%x,\n", frame->plbu_commands_end);
	wrap_log("\t.frame.tile_heap_start = 0x%x,\n", frame->tile_heap_start);
	wrap_log("\t.frame.tile_heap_end = 0x%x,\n", frame->tile_heap_end);

	wrap_log("};\n\n");

	mali_memory_dump();
}

struct lima_m400_pp_frame_registers {
	unsigned int plbu_array_address;
	unsigned int render_address;
	unsigned int unused_0;
	unsigned int flags;
	unsigned int clear_value_depth;
	unsigned int clear_value_stencil;
	unsigned int clear_value_color; /* rgba */
	unsigned int clear_value_color_1; /* copy of the above. */
	unsigned int clear_value_color_2; /* copy of the above. */
	unsigned int clear_value_color_3; /* copy of the above. */
	/* these two are only set if width or height are not 16 aligned. */
	unsigned int width; /* width - 1; */
	unsigned int height; /* height - 1; */
	unsigned int fragment_stack_address;
	unsigned int fragment_stack_size; /* start << 16 | end */
	unsigned int unused_1;
	unsigned int unused_2;
	unsigned int one; /* always set to 1 */
	/* When off screen, set to 1 */
	unsigned int supersampled_height; /* height << supersample factor */
	unsigned int dubya; /* 0x77 */
	unsigned int onscreen; /* 0 for FBO's, 1 for other rendering */
	/* max_step = max(step_x, step_y) */
	/* (max_step > 2) ? max_step = 2 : ; */
	unsigned int blocking; /* (max_step << 28) | (step_y << 16) | (step_x) */
	unsigned int scale; /* without supersampling, this is always 0x10C */
	unsigned int foureight; /* always 0x8888, perhaps on 4x pp this is different? */
};

enum lima_pp_wb_type {
	LIMA_PP_WB_TYPE_DISABLED = 0,
	LIMA_PP_WB_TYPE_OTHER = 1, /* for depth, stencil buffers, and fbo's */
	LIMA_PP_WB_TYPE_COLOR = 2, /* for color buffers */
};

struct lima_pp_wb_registers {
	unsigned int type;
	unsigned int address;
	unsigned int pixel_format; /* see formats.h */
	unsigned int downsample_factor;
	unsigned int pixel_layout; /* todo: see formats.h */
	unsigned int pitch; /* If layout is 2, then (width + 0x0F) / 16, else pitch / 8 */
	unsigned int zero;
	unsigned int mrt_bits; /* bits 0-3 are set for each of up to 4 render targets */
	unsigned int mrt_pitch; /* address pitch between render targets */
	unsigned int unused0;
	unsigned int unused1;
	unsigned int unused2;
};

static void
dev_mali_pp_job_start_pre(void *data)
{
        _mali_uk_pp_start_job_s *job = data;
	struct lima_m400_pp_frame_registers *frame = (void *)job->frame_registers;
	struct lima_pp_wb_registers *wb0 = (void *)job->wb0_registers;
	struct lima_pp_wb_registers *wb1 = (void *)job->wb1_registers;
	struct lima_pp_wb_registers *wb2 = (void *)job->wb2_registers;
	int i;

	wrap_log("/* IOCTL MALI_IOC_PP_START_JOB IN; */\n");

	wrap_log("_mali_uk_pp_start_job_s pp_job = {\n");

	wrap_log("\t.user_job_ptr = 0x%x,\n", job->user_job_ptr);
	wrap_log("\t.priority = 0x%x,\n", job->priority);

	wrap_log("\t.frame.plbu_array_address = 0x%x,\n", frame->plbu_array_address);
	wrap_log("\t.frame.render_address = 0x%x,\n", frame->render_address);
	wrap_log("\t.frame.unused_0 = 0x%x,\n", frame->unused_0);
	wrap_log("\t.frame.flags = 0x%x,\n", frame->flags);
	wrap_log("\t.frame.clear_value_depth = 0x%x,\n", frame->clear_value_depth);
	wrap_log("\t.frame.clear_value_stencil = 0x%x,\n", frame->clear_value_stencil);
	wrap_log("\t.frame.clear_value_color = 0x%x,\n", frame->clear_value_color);
	wrap_log("\t.frame.clear_value_color_1 = 0x%x,\n", frame->clear_value_color_1);
	wrap_log("\t.frame.clear_value_color_2 = 0x%x,\n", frame->clear_value_color_2);
	wrap_log("\t.frame.clear_value_color_3 = 0x%x,\n", frame->clear_value_color_3);
	wrap_log("\t.frame.width = 0x%x,\n", frame->width);
	wrap_log("\t.frame.height = 0x%x,\n", frame->height);
	wrap_log("\t.frame.fragment_stack_address = 0x%x,\n", frame->fragment_stack_address);
	wrap_log("\t.frame.fragment_stack_size = 0x%x,\n", frame->fragment_stack_size);
	wrap_log("\t.frame.one = 0x%x,\n", frame->one);
	wrap_log("\t.frame.supersampled_height = 0x%x,\n", frame->supersampled_height);
	wrap_log("\t.frame.dubya = 0x%x,\n", frame->dubya);
	wrap_log("\t.frame.onscreen = 0x%x,\n", frame->onscreen);
	wrap_log("\t.frame.blocking = 0x%x,\n", frame->blocking);
	wrap_log("\t.frame.scale = 0x%x,\n", frame->scale);
	wrap_log("\t.frame.foureight = 0x%x,\n", frame->foureight);

	for (i = 0; i < 7; i++)
		wrap_log("\t.addr_frame[%d] = 0x%x,\n", i, job->frame_registers_addr_frame[i]);
	for (i = 0; i < 7; i++)
		wrap_log("\t.addr_stack[%d] = 0x%x,\n", i, job->frame_registers_addr_stack[i]);

	wrap_log("\t.wb0.type = 0x%x,\n", wb0->type);
	wrap_log("\t.wb0.address = 0x%x,\n", wb0->address);
	wrap_log("\t.wb0.pixel_format = 0x%x,\n", wb0->pixel_format);
	wrap_log("\t.wb0.downsample_factor = 0x%x,\n", wb0->downsample_factor);
	wrap_log("\t.wb0.pixel_layout = 0x%x,\n", wb0->pixel_layout);
	wrap_log("\t.wb0.pitch = 0x%x,\n", wb0->pitch);
	wrap_log("\t.wb0.zero = 0x%x,\n", wb0->zero);
	wrap_log("\t.wb0.mrt_bits = 0x%x,\n", wb0->mrt_bits);
	wrap_log("\t.wb0.mrt_pitch = 0x%x,\n", wb0->mrt_pitch);

	wrap_log("\t.wb1.address = 0x%x,\n", wb1->address);
	wrap_log("\t.wb1.pixel_format = 0x%x,\n", wb1->pixel_format);
	wrap_log("\t.wb1.downsample_factor = 0x%x,\n", wb1->downsample_factor);
	wrap_log("\t.wb1.pixel_layout = 0x%x,\n", wb1->pixel_layout);
	wrap_log("\t.wb1.pitch = 0x%x,\n", wb1->pitch);
	wrap_log("\t.wb1.zero = 0x%x,\n", wb1->zero);
	wrap_log("\t.wb1.mrt_bits = 0x%x,\n", wb1->mrt_bits);
	wrap_log("\t.wb1.mrt_pitch = 0x%x,\n", wb1->mrt_pitch);

	wrap_log("\t.wb2.address = 0x%x,\n", wb2->address);
	wrap_log("\t.wb2.pixel_format = 0x%x,\n", wb2->pixel_format);
	wrap_log("\t.wb2.downsample_factor = 0x%x,\n", wb2->downsample_factor);
	wrap_log("\t.wb2.pixel_layout = 0x%x,\n", wb2->pixel_layout);
	wrap_log("\t.wb2.pitch = 0x%x,\n", wb2->pitch);
	wrap_log("\t.wb2.zero = 0x%x,\n", wb2->zero);
	wrap_log("\t.wb2.mrt_bits = 0x%x,\n", wb2->mrt_bits);
	wrap_log("\t.wb2.mrt_pitch = 0x%x,\n", wb2->mrt_pitch);

	wrap_log("\t.dlbu_regs[0] = 0x%x,\n", job->dlbu_registers[0]);
	wrap_log("\t.dlbu_regs[1] = 0x%x,\n", job->dlbu_registers[1]);
	wrap_log("\t.dlbu_regs[2] = 0x%x,\n", job->dlbu_registers[2]);
	wrap_log("\t.dlbu_regs[3] = 0x%x,\n", job->dlbu_registers[3]);

	wrap_log("\t.num_cores = 0x%x,\n", job->num_cores);

	wrap_log("\t.frame_builder_id = 0x%x,\n", job->frame_builder_id);
	wrap_log("\t.flush_id = 0x%x,\n", job->flush_id);
	wrap_log("\t.flags = 0x%x,\n", job->flags);

	wrap_log("\t.fence = 0x%x,\n", job->fence);
	wrap_log("\t.timeline_point_ptr = 0x%x,\n", job->timeline_point_ptr);

	wrap_log("};\n");

	mali_mmu_dump(job->ctx);
}

static void
dev_mali_pp_and_gp_job_start_pre(void *data)
{
	_mali_uk_pp_and_gp_start_job_s *job = data;
	dev_mali_gp_job_start_pre(job->gp_args);
	dev_mali_pp_job_start_pre(job->pp_args);
}

static struct ioc_type {
	int type;
	char *name;
} ioc_types[] = {
	{MALI_IOC_CORE_BASE, "MALI_IOC_CORE_BASE"},
	{MALI_IOC_MEMORY_BASE, "MALI_IOC_MEMORY_BASE"},
	{MALI_IOC_PP_BASE, "MALI_IOC_PP_BASE"},
	{MALI_IOC_GP_BASE, "MALI_IOC_GP_BASE"},
	{MALI_IOC_PROFILING_BASE, "MALI_IOC_PROFILING_BASE"},
	{MALI_IOC_VSYNC_BASE, "MALI_IOC_VSYNC_BASE"},
	{0, NULL},
};

static char *
ioc_type_name(int type)
{
	int i;

	for (i = 0; ioc_types[i].name; i++)
		if (ioc_types[i].type == type)
			break;

	return ioc_types[i].name;
}

struct dev_mali_ioctl_table {
	int type;
	int nr;
	char *name;
	void (*pre)(void *data);
	void (*post)(void *data, int ret);
};

static struct dev_mali_ioctl_table ioctl_table[] = {
	{MALI_IOC_CORE_BASE, _MALI_UK_WAIT_FOR_NOTIFICATION, "CORE, WAIT_FOR_NOTIFICATION",
	 dev_mali_wait_for_notification_pre, dev_mali_wait_for_notification_post},
	{MALI_IOC_CORE_BASE, _MALI_UK_GET_API_VERSION, "CORE, GET_API_VERSION",
	 dev_mali_get_api_version_pre, dev_mali_get_api_version_post},

	{MALI_IOC_MEMORY_BASE, _MALI_UK_ATTACH_UMP_MEM, "MEMORY, ATTACH_UMP_MEM",
	 NULL, dev_mali_memory_attach_ump_mem_post},
	{MALI_IOC_MEMORY_BASE, _MALI_UK_MAP_EXT_MEM, "MEMORY, MAP_EXT_MEM",
	 NULL, dev_mali_memory_map_ext_mem_post},
	{MALI_IOC_MEMORY_BASE, _MALI_UK_UNMAP_EXT_MEM, "MEMORY, UNMAP_EXT_MEM",
	 NULL, dev_mali_memory_unmap_ext_mem_post},

	{MALI_IOC_PP_BASE, _MALI_UK_PP_START_JOB, "PP, START_JOB",
	 dev_mali_pp_job_start_pre, NULL},
	{MALI_IOC_PP_BASE, _MALI_UK_GET_PP_NUMBER_OF_CORES, "PP, GET_NUMBER_OF_CORES",
	 NULL, dev_mali_pp_number_of_cores_post},
	{MALI_IOC_PP_BASE, _MALI_UK_GET_PP_CORE_VERSION, "PP, GET_CORE_VERSION",
	 NULL, dev_mali_pp_core_version_post},
	{MALI_IOC_PP_BASE, _MALI_UK_PP_AND_GP_START_JOB, "GP&PP, START_JOB",
	 dev_mali_pp_and_gp_job_start_pre, NULL},

	{MALI_IOC_GP_BASE, _MALI_UK_GP_START_JOB, "GP, START_JOB",
	 dev_mali_gp_job_start_pre, NULL},
	{MALI_IOC_GP_BASE, _MALI_UK_GET_GP_NUMBER_OF_CORES, "GP, GET_NUMBER_OF_CORES",
	 NULL, dev_mali_gp_number_of_cores_post},
	{MALI_IOC_GP_BASE, _MALI_UK_GET_GP_CORE_VERSION, "GP, GET_CORE_VERSION",
	 NULL, dev_mali_gp_core_version_post},

	{ 0, 0, NULL, NULL, NULL}
};

static int
mali_ioctl(int request, void *data)
{
	struct dev_mali_ioctl_table *ioctl = NULL;
	int ioc_type = _IOC_TYPE(request);
	int ioc_nr = _IOC_NR(request);
	char *ioc_string = ioctl_dir_string(request);
	int i;
	int ret;

	for (i = 0; ioctl_table[i].name; i++) {
		if ((ioctl_table[i].type == ioc_type) &&
		    (ioctl_table[i].nr == ioc_nr)) {
			ioctl = &ioctl_table[i];
			break;
		}
	}

	if (!ioctl) {
		char *name = ioc_type_name(ioc_type);

		if (name)
			wrap_log("/* Error: No mali ioctl wrapping implemented for %s:%02X */\n",
				 name, ioc_nr);
		else
			wrap_log("/* Error: No mali ioctl wrapping implemented for %02X:%02X */\n",
				 ioc_type, ioc_nr);

	}

	if (ioctl && ioctl->pre)
		ioctl->pre(data);

	if (data)
		ret = orig_ioctl(dev_mali_fd, request, data);
	else
		ret = orig_ioctl(dev_mali_fd, request);

	if (ioctl && !ioctl->pre && !ioctl->post) {
		if (data)
			wrap_log("/* IOCTL %s(%s) %p = %d */\n",
				 ioc_string, ioctl->name, data, ret);
		else
			wrap_log("/* IOCTL %s(%s) = %d */\n",
				 ioc_string, ioctl->name, ret);
	}

	if (ioctl && ioctl->post)
		ioctl->post(data, ret);

	return ret;
}

/*
 *
 * Memory dumper.
 *
 */
#define MALI_ADDRESSES 0x40

static struct mali_address {
	void *address; /* mapped address */
	unsigned int size;
	unsigned int physical; /* actual address */
} mali_addresses[MALI_ADDRESSES];

static int
mali_address_add(void *address, unsigned int size, unsigned int physical)
{
	int i;

	for (i = 0; i < MALI_ADDRESSES; i++) {
		if ((mali_addresses[i].address >= address) &&
		    (mali_addresses[i].address < (address + size)) &&
		    ((mali_addresses[i].address + size) > address) &&
		    ((mali_addresses[i].address + size) <= (address + size))) {
			printf("Error: Address %p (0x%x) is already taken!\n",
			       address, size);
			return -1;
		}
	}

	for (i = 0; i < MALI_ADDRESSES; i++)
		if (!mali_addresses[i].address) {
			mali_addresses[i].address = address;
			mali_addresses[i].size = size;
			mali_addresses[i].physical = physical;
			return 0;
		}

	printf("Error: No more free memory slots for %p (0x%x)!\n",
	       address, size);
	return -1;
}

static int
mali_address_remove(void *address, int size)
{
	int i;

	for (i = 0; i < MALI_ADDRESSES; i++)
		if ((mali_addresses[i].address == address) &&
		    (mali_addresses[i].size == size)) {
			mali_addresses[i].address = NULL;
			mali_addresses[i].size = 0;
			mali_addresses[i].physical = 0;
			return 0;
		}

	return -1;
}

#define MALI_EXTERNALS 0x10
static struct mali_external {
	void *address;
	unsigned int physical; /* actual address */
	unsigned int size;
	unsigned int cookie;
} mali_externals[MALI_EXTERNALS];

static int
mali_external_add(void *address, unsigned int physical,
		  unsigned int size, unsigned int cookie)
{
	int i;

	for (i = 0; i < MALI_EXTERNALS; i++) {
		if ((mali_externals[i].address >= address) &&
		    (mali_externals[i].address < (address + size)) &&
		    ((mali_externals[i].address + size) > address) &&
		    ((mali_externals[i].address + size) <= (address + size))) {
			printf("Error: Address 0x%08X (0x%x) is already taken!\n",
			       address, size);
			return -1;
		}
	}

	for (i = 0; i < MALI_EXTERNALS; i++)
		if (!mali_externals[i].address)
			break;

	if (i == MALI_EXTERNALS) {
		printf("Error: No more free memory slots for 0x%08X (0x%x)!\n",
		       address, size);
		return -1;
	}

	/* map memory here */
	mali_externals[i].address = address;
	mali_externals[i].physical = physical;
	mali_externals[i].size = size;
	mali_externals[i].cookie = cookie;

	return 0;
}

static int
mali_external_remove(unsigned int cookie)
{
	int i;

	for (i = 0; i < MALI_EXTERNALS; i++)
		if (mali_externals[i].cookie == cookie) {
			/* deref mapping here */

			mali_externals[i].address = 0;
			mali_externals[i].physical = 0;
			mali_externals[i].size = 0;
			mali_externals[i].cookie = 0;

			return 0;
		}

	return -1;
}

#define UMP_ADDRESSES 0x10

static struct ump_address {
	void *address; /* mapped address */
	unsigned int id;
	unsigned int size;
	unsigned int physical; /* actual address */
} ump_addresses[UMP_ADDRESSES];

static int
ump_id_add(unsigned int id, unsigned int size, void *address)
{
	int i;

	for (i = 0; i < UMP_ADDRESSES; i++)
		if (!ump_addresses[i].id) {
			ump_addresses[i].id = id;
			ump_addresses[i].size = size;
			ump_addresses[i].address = address;
			return 0;
		}

	printf("%s: No more free slots for 0x%08X (0x%x)!\n",
	       __func__, id, size);
	return -1;
}

static int
ump_physical_add(unsigned int id, unsigned int physical)
{
	int i;

	for (i = 0; i < UMP_ADDRESSES; i++)
		if (ump_addresses[i].id == id) {
			ump_addresses[i].physical = physical;
			return 0;
		}

	printf("%s: Error: id 0x%08X not found!\n", __func__, id);
	return -1;
}

static void *
mali_address_retrieve(unsigned int physical)
{
	int i;

	for (i = 0; i < MALI_EXTERNALS; i++)
		if ((mali_externals[i].address <= (void *)physical) &&
		    ((mali_externals[i].address + mali_externals[i].size)
		     >= (void *)physical))
			return mali_externals[i].address +
				(mali_externals[i].physical - physical);

	for (i = 0; i < MALI_ADDRESSES; i++)
		if ((mali_addresses[i].physical <= physical) &&
		    ((mali_addresses[i].physical + mali_addresses[i].size)
		     >= physical))
			return mali_addresses[i].address +
				(mali_addresses[i].physical - physical);


	for (i = 0; i < UMP_ADDRESSES; i++)
		if ((ump_addresses[i].physical <= physical) &&
		    ((ump_addresses[i].physical + ump_addresses[i].size)
		     >= physical)) {
			if (ump_addresses[i].address)
				return ump_addresses[i].address +
					(ump_addresses[i].physical - physical);
			else
				return NULL;
		}

	return NULL;
}

static void
mali_memory_dump_block(unsigned int *address, int start, int stop,
		       unsigned physical, int count)
{
	int i;

	wrap_log("static struct lima_dumped_mem_content mem_0x%08x_0x%08x = {\n",
	       physical, count);

	wrap_log("\t0x%08x,\n", 4 * start);
	wrap_log("\t0x%08x,\n", 4 * (stop - start));
	wrap_log("\t{\n");

	for (i = start; i < stop; i += 4)
		wrap_log("\t\t0x%08x, 0x%08x, 0x%08x, 0x%08x, /* 0x%08X */\n",
			 address[i + 0], address[i + 1],
			 address[i + 2], address[i + 3], 4 * (i - start));

	wrap_log("\t}\n");
	wrap_log("};\n\n");
}

static void
mali_memory_dump_address(unsigned int *address, unsigned int size,
			 unsigned int physical)
{
	int i, start = -1, stop = -1, count = 0;

	for (i = 0; i < size; i += 4) {
		if (start == -1) {
			if (address[i + 0] || address[i + 1] ||
			    address[i + 2] || address[i + 3])
				start = i;
		} else if (stop == -1) {
			if (!address[i + 0] && !address[i + 1] &&
			    !address[i + 2] && !address[i + 3])
				stop = i;
		} else if (!address[i + 0] && !address[i + 1] &&
			   !address[i + 2] && !address[i + 3]) {
			if (i > (stop + 2)) {
				mali_memory_dump_block(address, start, stop,
						       physical, count);
				count++;
				start = -1;
				stop = -1;
			}
		} else
			stop = -1;
	}

	if (start != -1) {
		if (stop == -1) {
			mali_memory_dump_block(address, start, size, physical, count);
			count++;
		} else {
			mali_memory_dump_block(address, start, stop, physical, count);
			count++;
		}
	}

	wrap_log("static struct lima_dumped_mem_block mem_0x%08x = {\n", physical);
	wrap_log("\tNULL,\n");
	wrap_log("\t0x%08x,\n", physical);
	wrap_log("\t0x%08x,\n", 4 * size);
	wrap_log("\t0x%08x,\n", count);
	wrap_log("\t{\n");

	for (i = 0; i < count; i++)
		wrap_log("\t\t&mem_0x%08x_0x%08x,\n", physical, i);

	wrap_log("\t},\n");
	wrap_log("};\n\n");
}

static void
mali_memory_dump(void)
{
	int i, count = 0;

	for (i = 0; i < MALI_ADDRESSES; i++)
		if (mali_addresses[i].address) {
			mali_memory_dump_address(mali_addresses[i].address,
						 mali_addresses[i].size / 4,
						 mali_addresses[i].physical);
			count++;
		}

	wrap_log("struct lima_dumped_mem dumped_mem = {\n");
	wrap_log("\t0x%08x,\n", count);
	wrap_log("\t{\n");

	for (i = 0; i < MALI_ADDRESSES; i++)
		if (mali_addresses[i].address)
			wrap_log("\t\t&mem_0x%08x,\n", mali_addresses[i].physical);

	wrap_log("\t},\n");
	wrap_log("};\n\n");
}

static void
mali_mmu_dump(void *ctx)
{
	_mali_uk_query_mmu_page_table_dump_size_s req1 = {
		.ctx = ctx,
		.size = 0,
	};
	_mali_uk_dump_mmu_page_table_s req2;
	int ret;
	uint32_t i, j;
	uint32_t *buffer, *pde, *pte;

	if (!orig_ioctl)
		orig_ioctl = libc_dlsym(__func__);

	ret = orig_ioctl(dev_mali_fd, MALI_IOC_MEM_QUERY_MMU_PAGE_TABLE_DUMP_SIZE, &req1);
	if (ret) {
		fprintf(stderr, "%s: fail to get dump size\n", __func__);
		return;
	}

	buffer = calloc(1, req1.size);
	if (!buffer) {
		fprintf(stderr, "%s: fail to alloc mem\n", __func__);
		return;
	}

	req2.ctx = ctx;
	req2.size = req1.size;
	req2.buffer = buffer;
	ret = orig_ioctl(dev_mali_fd, MALI_IOC_MEM_DUMP_MMU_PAGE_TABLE, &req2);
	if (ret) {
		fprintf(stderr, "%s: fail to get dump\n", __func__);
		free(buffer);
		return;
	}

	wrap_log("\ndump pd %08x\n", *req2.page_table_dump);
	pde = req2.page_table_dump + 1;
	pte = req2.page_table_dump + 1 + 1024;
	for (i = 0; i < 1024; i++) {
		if (pde[i]) {
			wrap_log("%03d pde %08x pt %08x\n", i, pde[i], *pte++);
			for (j = 0; j < 1024; j++) {
				if (pte[j])
					wrap_log("  va %08x pte %08x\n",
						 (i << 22) | (j << 12), pte[j]);
			}
			pte += 1024;
		}
	}
	wrap_log("\n\n");

	free(buffer);
}
