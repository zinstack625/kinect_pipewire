/*
 * This file is part of the OpenKinect Project. http://www.openkinect.org
 *
 * Copyright (c) 2011 individual OpenKinect contributors. See the CONTRIB file
 * for details.
 *
 * This code is licensed to you under the terms of the Apache License, version
 * 2.0, or, at your option, the terms of the GNU General Public License,
 * version 2.0. See the APACHE20 and GPL2 files for the text of the licenses,
 * or the following URLs:
 * http://www.apache.org/licenses/LICENSE-2.0
 * http://www.gnu.org/licenses/gpl-2.0.txt
 *
 * If you redistribute this file in source form, modified or unmodified, you
 * may:
 *   1) Leave this header intact and distribute it under the same terms,
 *      accompanying it with the APACHE20 and GPL20 files, or
 *   2) Delete the Apache 2.0 clause and accompany it with the GPL2 file, or
 *   3) Delete the GPL v2 clause and accompany it with the APACHE20 file
 * In all cases you must keep the copyright notice intact and include a copy
 * of the CONTRIB file.
 *
 * Binary distributions must follow the binary distribution requirements of
 * either License.
 */

#include <libfreenect/libfreenect.h>
#include <libfreenect/libfreenect_audio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>


#include <spa/utils/result.h>
#include <spa/utils/string.h>
#include <spa/utils/json.h>
#include <spa/utils/ringbuffer.h>
#include <spa/debug/pod.h>
#include <spa/pod/builder.h>
#include <spa/param/audio/format-utils.h>
#include <spa/param/audio/raw.h>

#include <pipewire/impl.h>
#include <pipewire/i18n.h>


#define GAIN_COEFF 32

pthread_t freenect_thread;
pthread_t freenect_thread_watcher;
volatile int die = 0;

int window;

static freenect_context* f_ctx;
static freenect_device* f_dev;

typedef struct {
  int32_t* buffer;
  int max_samples;
  int prev_idx;
  int current_idx;  // index to the oldest data in the buffer (equivalently, where the next new data will be placed)
  int new_data;
} capture;

capture state;

int paused = 0;

pthread_mutex_t audiobuf_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t audiobuf_cond = PTHREAD_COND_INITIALIZER;

int win_h, win_w;

void gain(int coeff, int32_t* buffer, size_t size) {
  for (size_t i = 0; i < size; ++i)
    buffer[i] *= coeff;
}

void in_callback(freenect_device* dev, int num_samples,
                 int32_t* mic1, int32_t* mic2,
                 int32_t* mic3, int32_t* mic4,
                 int16_t* cancelled, void *unknown) {
  pthread_mutex_lock(&audiobuf_mutex);
  capture* c = (capture*)freenect_get_user(dev);
  if(num_samples < c->max_samples - c->current_idx) {
    for (size_t i = 0; i < num_samples; ++i)
      c->buffer[c->current_idx + i] = mic1[i] / 4 + mic2[i] / 4 + mic3[i] / 4 + mic4[i] / 4;
    gain(GAIN_COEFF, c->buffer + c->current_idx, num_samples); 
  } else {
    int first = c->max_samples - c->current_idx;
    int left = num_samples - first;
    for (size_t i = 0; i < first; ++i)
      c->buffer[c->current_idx + i] = mic1[i] / 4 + mic2[i] / 4 + mic3[i] / 4 + mic4[i] / 4;
    gain(GAIN_COEFF, c->buffer + c->current_idx, first);
    for (size_t i = 0; i < left; ++i)
      c->buffer[i] = mic1[i] / 4 + mic2[i] / 4 + mic3[i] / 4 + mic4[i] / 4;
    gain(GAIN_COEFF, c->buffer, left);
  }
  c->current_idx = (c->current_idx + num_samples) % c->max_samples;
  c->new_data = 1;
  pthread_cond_signal(&audiobuf_cond);
  pthread_mutex_unlock(&audiobuf_mutex);
}

void* freenect_threadfunc(void* arg) {
  while(!die && freenect_process_events(f_ctx) >= 0);
  freenect_stop_audio(f_dev);
  freenect_close_device(f_dev);
  freenect_shutdown(f_ctx);
  free(state.buffer);
  return NULL;
}

/* PipeWire
 *
 * Copyright © 2021 Wim Taymans and Anton Klimanov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define NAME "kinect-source"

#define DEFAULT_FORMAT "S32LE"
#define DEFAULT_RATE "16000"
#define DEFAULT_CHANNELS "1"
#define DEFAULT_POSITION "[ MONO ]"

#define MODULE_USAGE  "[ node.latency=<latency as fraction> ] "        \
      "[ node.name=<name of the nodes> ] "          \
      "[ node.description=<description of the nodes> ] "      \
      "[ audio.format=<format, default:"DEFAULT_FORMAT"> ] "      \
      "[ audio.rate=<sample rate, default:"DEFAULT_RATE"> ] "      \
      "[ audio.channels=<number of channels, default:"DEFAULT_CHANNELS"> ] "  \
      "[ audio.position=<channel map, default:"DEFAULT_POSITION"> ] "    \
      "[ stream.props=<properties> ] "


static const struct spa_dict_item module_props[] = {
  { PW_KEY_MODULE_AUTHOR, "Anton Klimanov <klimanov625@outlook.com>" },
  { PW_KEY_MODULE_DESCRIPTION, "Audio source from Xbox 360's kinect, utilising freenect" },
  { PW_KEY_MODULE_USAGE, MODULE_USAGE },
  { PW_KEY_MODULE_VERSION, "0.1" },
};

struct impl {
  struct pw_context *context;

  struct pw_properties *props;

  struct pw_impl_module *module;
  struct pw_work_queue *work;

  struct spa_hook module_listener;

  struct pw_core *core;
  struct spa_hook core_proxy_listener;
  struct spa_hook core_listener;

  struct pw_properties *stream_props;
  struct pw_stream *stream;
  struct spa_hook stream_listener;
  struct spa_io_rate_match *rate_match;
  struct spa_audio_info_raw info;
  uint32_t frame_size;

  unsigned int do_disconnect:1;
  unsigned int unloading:1;
};

static void do_unload_module(void *obj, void *data, int res, uint32_t id)
{
  struct impl *impl = data;
  pw_impl_module_destroy(impl->module);
}

static void unload_module(struct impl *impl)
{
  if (!impl->unloading) {
    impl->unloading = true;
    pw_work_queue_add(impl->work, impl, 0, do_unload_module, impl);
  }
}

static void stream_destroy(void *d)
{
  struct impl *impl = d;
  spa_hook_remove(&impl->stream_listener);
  impl->stream = NULL;
  die = 1;
}

static void stream_state_changed(void *d, enum pw_stream_state old,
    enum pw_stream_state state, const char *error)
{
  struct impl *impl = d;
  switch (state) {
  case PW_STREAM_STATE_ERROR:
  case PW_STREAM_STATE_UNCONNECTED:
    unload_module(impl);
    break;
  case PW_STREAM_STATE_PAUSED:
    paused = 1;
  case PW_STREAM_STATE_STREAMING:
    paused = 0;
    break;
  default:
    break;
  }
}

static void capture_stream_process(void *d)
{
  struct impl *impl = d;
  struct pw_buffer *buf;
  struct spa_data *bd;
  void *data;
  uint32_t size;

  if ((buf = pw_stream_dequeue_buffer(impl->stream)) == NULL) {
    pw_log_debug("out of buffers: %m");
    return;
  }

  bd = &buf->buffer->datas[0];

  data = bd->data;
  if (impl->rate_match)
    size = SPA_MIN(impl->rate_match->size * impl->frame_size, bd->maxsize);
  else
    size = bd->maxsize;
  int copied = 0;
  pthread_mutex_lock(&audiobuf_mutex);
  if (state.new_data) {
    if ((state.current_idx - state.prev_idx) * sizeof(int32_t) <= size) {
      if (state.current_idx > state.prev_idx) {
        memcpy(data, state.buffer + state.prev_idx, (state.current_idx - state.prev_idx) * sizeof(int32_t));
        copied = (state.current_idx - state.prev_idx) * sizeof(int32_t);
      } else {
        int first = state.max_samples - state.prev_idx;
        int left = state.current_idx;
        memcpy(data, state.buffer, first * sizeof(int32_t));
        memcpy(data + first * sizeof(int32_t), state.buffer, left * sizeof(int32_t));
        copied = first + left;
      }
      state.new_data = 0;
      state.prev_idx = state.current_idx;
    } else {
      if (state.current_idx > state.prev_idx) {
          memcpy(data, state.buffer + state.prev_idx, size);
          copied = size / sizeof(int32_t);
          state.prev_idx += copied;
      } else {
        int first = state.max_samples - state.prev_idx;
        if (first * sizeof(int32_t) < size) {
          memcpy(data, state.buffer, first * sizeof(int32_t));
          copied = first;
        } else {
          memcpy(data, state.buffer, size);
        }
        memcpy(data + first * sizeof(int32_t), state.buffer, size - copied * sizeof(int32_t));
        copied = size / sizeof(int32_t);
        state.prev_idx = size / sizeof(int32_t) - copied;
      }
    }
  }
  pthread_mutex_unlock(&audiobuf_mutex);
  pw_log_info("fill buffer data %p with up to %u bytes", data, size);

  bd->chunk->size = size;
  bd->chunk->stride = impl->frame_size;
  bd->chunk->offset = 0;

  pw_stream_queue_buffer(impl->stream, buf);
}

static void stream_io_changed(void *data, uint32_t id, void *area, uint32_t size)
{
  struct impl *impl = data;
  switch (id) {
  case SPA_IO_RateMatch:
    impl->rate_match = area;
    break;
  }
}

static const struct pw_stream_events capture_stream_events = {
  PW_VERSION_STREAM_EVENTS,
  .destroy = stream_destroy,
  .state_changed = stream_state_changed,
  .io_changed = stream_io_changed,
  .process = capture_stream_process
};

static int create_stream(struct impl *impl)
{
  int res;
  uint32_t n_params;
  const struct spa_pod *params[1];
  uint8_t buffer[1024];
  struct spa_pod_builder b;

  impl->stream = pw_stream_new(impl->core, "kinect source", impl->stream_props);
  impl->stream_props = NULL;

  if (impl->stream == NULL)
    return -errno;

  pw_stream_add_listener(impl->stream,
      &impl->stream_listener,
      &capture_stream_events, impl);

  n_params = 0;
  spa_pod_builder_init(&b, buffer, sizeof(buffer));
  params[n_params++] = spa_format_audio_raw_build(&b,
      SPA_PARAM_EnumFormat, &impl->info);

  if ((res = pw_stream_connect(impl->stream,
      PW_DIRECTION_OUTPUT,
      PW_ID_ANY,
      PW_STREAM_FLAG_AUTOCONNECT |
      PW_STREAM_FLAG_MAP_BUFFERS |
      PW_STREAM_FLAG_RT_PROCESS,
      params, n_params)) < 0)
    return res;

  return 0;
}

static void core_error(void *data, uint32_t id, int seq, int res, const char *message)
{
  struct impl *impl = data;

  pw_log_error("error id:%u seq:%d res:%d (%s): %s",
      id, seq, res, spa_strerror(res), message);

  if (id == PW_ID_CORE && res == -EPIPE)
    unload_module(impl);
}

static const struct pw_core_events core_events = {
  PW_VERSION_CORE_EVENTS,
  .error = core_error,
};

static void core_destroy(void *d)
{
  struct impl *impl = d;
  spa_hook_remove(&impl->core_listener);
  impl->core = NULL;
  unload_module(impl);
}

static const struct pw_proxy_events core_proxy_events = {
  .destroy = core_destroy,
};

static void impl_destroy(struct impl *impl)
{
  if (impl->stream)
    pw_stream_destroy(impl->stream);
  if (impl->core && impl->do_disconnect)
    pw_core_disconnect(impl->core);

  pw_properties_free(impl->stream_props);
  pw_properties_free(impl->props);

  if (impl->work)
    pw_work_queue_cancel(impl->work, impl, SPA_ID_INVALID);
  free(impl);
}

static void module_destroy(void *data)
{
  struct impl *impl = data;
  impl->unloading = true;
  spa_hook_remove(&impl->module_listener);
  impl_destroy(impl);
}

static const struct pw_impl_module_events module_events = {
  PW_VERSION_IMPL_MODULE_EVENTS,
  .destroy = module_destroy,
};

static inline uint32_t format_from_name(const char *name, size_t len)
{
  int i;
  for (i = 0; spa_type_audio_format[i].name; i++) {
    if (strncmp(name, spa_debug_type_short_name(spa_type_audio_format[i].name), len) == 0)
      return spa_type_audio_format[i].type;
  }
  return SPA_AUDIO_FORMAT_UNKNOWN;
}

static uint32_t channel_from_name(const char *name)
{
  int i;
  for (i = 0; spa_type_audio_channel[i].name; i++) {
    if (spa_streq(name, spa_debug_type_short_name(spa_type_audio_channel[i].name)))
      return spa_type_audio_channel[i].type;
  }
  return SPA_AUDIO_CHANNEL_UNKNOWN;
}

static void parse_position(struct spa_audio_info_raw *info, const char *val, size_t len)
{
  struct spa_json it[2];
  char v[256];

  spa_json_init(&it[0], val, len);
        if (spa_json_enter_array(&it[0], &it[1]) <= 0)
                spa_json_init(&it[1], val, len);

  info->channels = 0;
  while (spa_json_get_string(&it[1], v, sizeof(v)) > 0 &&
      info->channels < SPA_AUDIO_MAX_CHANNELS) {
    info->position[info->channels++] = channel_from_name(v);
  }
}

static int parse_audio_info(struct impl *impl)
{
  struct pw_properties *props = impl->stream_props;
  struct spa_audio_info_raw *info = &impl->info;
  const char *str;

  spa_zero(*info);

  if ((str = pw_properties_get(props, PW_KEY_AUDIO_FORMAT)) == NULL)
    str = DEFAULT_FORMAT;
  info->format = format_from_name(str, strlen(str));
  switch (info->format) {
  case SPA_AUDIO_FORMAT_S8:
  case SPA_AUDIO_FORMAT_U8:
    impl->frame_size = 1;
    break;
  case SPA_AUDIO_FORMAT_S16:
    impl->frame_size = 2;
    break;
  case SPA_AUDIO_FORMAT_S24:
    impl->frame_size = 3;
    break;
  case SPA_AUDIO_FORMAT_S24_32:
  case SPA_AUDIO_FORMAT_S32:
  case SPA_AUDIO_FORMAT_F32:
    impl->frame_size = 4;
    break;
  case SPA_AUDIO_FORMAT_F64:
    impl->frame_size = 8;
    break;
  default:
    pw_log_error("unsupported format '%s'", str);
    return -EINVAL;
  }
  if ((str = pw_properties_get(props, PW_KEY_AUDIO_RATE)) == NULL)
    str = DEFAULT_RATE;
  info->rate = atoi(str);
  if (info->rate == 0) {
    pw_log_error("invalid rate '%s'", str);
    return -EINVAL;
  }
  if ((str = pw_properties_get(props, PW_KEY_AUDIO_CHANNELS)) == NULL)
    str = DEFAULT_CHANNELS;
  info->channels = atoi(str);
  if ((str = pw_properties_get(props, SPA_KEY_AUDIO_POSITION)) == NULL)
    str = DEFAULT_POSITION;
  parse_position(info, str, strlen(str));
  if (info->channels == 0) {
    pw_log_error("invalid channels '%s'", str);
    return -EINVAL;
  }
  impl->frame_size *= info->channels;

  return 0;
}

static void copy_props(struct impl *impl, struct pw_properties *props, const char *key)
{
  const char *str;
  if ((str = pw_properties_get(props, key)) != NULL) {
    if (pw_properties_get(impl->stream_props, key) == NULL)
      pw_properties_set(impl->stream_props, key, str);
  }
}


SPA_EXPORT
int pipewire__module_init(struct pw_impl_module* module, const char* args) {
  // get and init kinect
  if (freenect_init(&f_ctx, NULL) < 0) {
    pw_log_error("freenect_init() failed");
    return 1;
  }
  freenect_set_log_level(f_ctx, FREENECT_LOG_INFO);
  freenect_select_subdevices(f_ctx, FREENECT_DEVICE_AUDIO);

  int nr_devices = freenect_num_devices (f_ctx);
  if (nr_devices < 1) {
    freenect_shutdown(f_ctx);
    return 1;
  }

  int user_device_number = 0;
  if (freenect_open_device(f_ctx, &f_dev, user_device_number) < 0) {
    pw_log_error("Could not open device");
    freenect_shutdown(f_ctx);
    return 1;
  }

  state.max_samples = 256 * 60;
  state.current_idx = 0;

  state.buffer = (int32_t*)malloc(state.max_samples * sizeof(int32_t));

  freenect_set_user(f_dev, &state);

  freenect_set_audio_in_callback(f_dev, in_callback);
  freenect_start_audio(f_dev);

  int processor_thread = pthread_create(&freenect_thread, NULL, freenect_threadfunc, NULL);
  if (processor_thread) {
    pw_log_error("pthread_create failed");
    freenect_shutdown(f_ctx);
    return 1;
  }
  // kinect inited
  
  struct pw_context* context = pw_impl_module_get_context(module);
  uint32_t id = pw_global_get_id(pw_impl_module_get_global(module));
  struct pw_properties* props = NULL;
  struct impl* impl;
  const char* str;
  int res;
  
  impl = calloc(1, sizeof(struct impl));
  if (!impl) return -errno;

  pw_log_debug("module %p: new %s", impl, args);

  if (!args) args = "";

  props = pw_properties_new_string(args);
  if (!props) {
    res = -errno;
    pw_log_error("can't create props: %m");
    goto error;
  }
  impl->props = props;
  impl->stream_props = pw_properties_new(NULL, NULL);
  if (impl->stream_props == NULL) {
    res = -errno;
    pw_log_error("can't create props: %m");
    goto error;
  }
  impl->module = module;
  impl->context = context;
  impl->work = pw_context_get_work_queue(context);
  if (impl->work == NULL) {
    res = -errno;
    pw_log_error("can't get work queue: %m");
    goto error;
  }

  if (pw_properties_get(props, PW_KEY_NODE_GROUP) == NULL)
    pw_properties_set(props, PW_KEY_NODE_GROUP, "pipewire.dummy");
  if (pw_properties_get(props, PW_KEY_NODE_VIRTUAL) == NULL)
    pw_properties_set(props, PW_KEY_NODE_VIRTUAL, "true");

  if (pw_properties_get(props, PW_KEY_MEDIA_CLASS) == NULL)
    pw_properties_set(props, PW_KEY_MEDIA_CLASS, "Audio/Source");

  if (pw_properties_get(props, PW_KEY_NODE_NAME) == NULL)
    pw_properties_setf(props, PW_KEY_NODE_NAME, "Kinect Source-%u", id);
  if (pw_properties_get(props, PW_KEY_NODE_DESCRIPTION) == NULL)
    pw_properties_set(props, PW_KEY_NODE_DESCRIPTION,
        pw_properties_get(props, PW_KEY_NODE_NAME));

  if ((str = pw_properties_get(props, "stream.props")) != NULL)
    pw_properties_update_string(impl->stream_props, str, strlen(str));

  copy_props(impl, props, PW_KEY_AUDIO_RATE);
  copy_props(impl, props, PW_KEY_AUDIO_CHANNELS);
  copy_props(impl, props, SPA_KEY_AUDIO_POSITION);
  copy_props(impl, props, PW_KEY_NODE_NAME);
  copy_props(impl, props, PW_KEY_NODE_DESCRIPTION);
  copy_props(impl, props, PW_KEY_NODE_GROUP);
  copy_props(impl, props, PW_KEY_NODE_LATENCY);
  copy_props(impl, props, PW_KEY_NODE_VIRTUAL);
  copy_props(impl, props, PW_KEY_MEDIA_CLASS);

  if ((res = parse_audio_info(impl)) < 0) {
    pw_log_error( "can't parse audio format");
    goto error;
  }

  impl->core = pw_context_get_object(impl->context, PW_TYPE_INTERFACE_Core);
  if (impl->core == NULL) {
    str = pw_properties_get(props, PW_KEY_REMOTE_NAME);
    impl->core = pw_context_connect(impl->context,
        pw_properties_new(
          PW_KEY_REMOTE_NAME, str,
          NULL),
        0);
    impl->do_disconnect = true;
  }
  if (impl->core == NULL) {
    res = -errno;
    pw_log_error("can't connect: %m");
    goto error;
  }
  pw_proxy_add_listener((struct pw_proxy*)impl->core,
        &impl->core_proxy_listener,
        &core_proxy_events, impl);
   pw_core_add_listener(impl->core,
        &impl->core_listener,
        &core_events, impl);
  
   if ((res = create_stream(impl)) < 0)
     goto error;
  
   pw_impl_module_add_listener(module, &impl->module_listener, &module_events, impl);
  
   pw_impl_module_update_properties(module, &SPA_DICT_INIT_ARRAY(module_props));

  return 0;

error:
  impl_destroy(impl);
  return res;

}
