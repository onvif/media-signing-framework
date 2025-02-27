/**
 * MIT License
 *
 * Copyright (c) 2025 ONVIF. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph)
 * shall be included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * This application signs a video captured and stored in a file.
 *
 * The output file name is the input file name prepended with 'signed_', that is,
 * <filename> in becomes signed_<filename> out.
 *
 * Supported video codecs are H.264 and H.265 and the recording can be .mp4, .mkv, .h264,
 * .h265.
 *
 * Example to sign a H.264 (default) video stored in file.mp4
 *   $ ./signer /path/to/file.mp4
 *
 * Example to sign a H.265 video stored in file.mp4
 *   $ ./signer -c h265 /path/to/file.mp4
 */

#include <gst/gst.h>
#include <string.h>  // strcmp, strncmp

#include "gst-plugin/gstsigning_defines.h"

#ifndef ATTR_UNUSED
#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
#endif

/* Callback to get and read messages on the bus. */
static gboolean
bus_call(GstBus ATTR_UNUSED *bus, GstMessage *msg, gpointer data)
{
  GMainLoop *loop = data;

  switch (GST_MESSAGE_TYPE(msg)) {
    case GST_MESSAGE_EOS:
      g_message("End-of-stream");
      g_main_loop_quit(loop);
      break;
    case GST_MESSAGE_ERROR: {
      gchar *debug = NULL;
      GError *err = NULL;

      gst_message_parse_error(msg, &err, &debug);
      g_message("Error: %s", err->message);
      g_error_free(err);

      if (debug) {
        g_message("Debug details: %s", debug);
        g_free(debug);
      }

      g_main_loop_quit(loop);
      break;
    }
    case GST_MESSAGE_ELEMENT: {
      const GstStructure *s = gst_message_get_structure(msg);
      if (strcmp(gst_structure_get_name(s), SIGNING_STRUCTURE_NAME) == 0) {
        const gchar *result = gst_structure_get_string(s, SIGNING_FIELD_NAME);
        g_message("GOP %s", result);
      }
      break;
    }
    default:
      break;
  }

  return TRUE;
}

/* Callback to link |element| and |data| (sink_element). */
static void
pad_added_cb(GstElement ATTR_UNUSED *element, GstPad *pad, gpointer data)
{
  GstElement *sink_element = data;
  GstPad *sinkpad = gst_element_get_static_pad(sink_element, "sink");
  if (gst_pad_link(pad, sinkpad) != GST_PAD_LINK_OK)
    g_printerr("Failed to link demux and parser");
  gst_object_unref(sinkpad);
}

gint
main(gint argc, gchar *argv[])
{
  int arg = 1;
  int status = 1;

  gchar *usage = g_strdup_printf(
      "Usage:\n%s [-h] [-c codec] filename\n\n"
      "Optional\n"
      "  -h, --help       : This usage print.\n"
      "  -c codec         : 'h264' (default if omitted) or 'h265'.\n"
      "Required\n"
      "  filename         : Name of the file to be signed.\n"
      "Output\n"
      "  signed_filename  : Name of the file to be signed.\n",
      argv[0]);

  GError *error = NULL;
  gchar *filename = NULL;
  gchar *outfilename = NULL;
  gchar *codec_str = "h264";
  gchar *demux_str = "qtdemux";
  gchar *mux_str = "mp4mux";

  GstElement *pipeline = NULL;
  GstElement *filesrc = NULL;
  GstElement *demuxer = NULL;
  GstElement *parser = NULL;
  GstElement *mediasigning = NULL;
  GstElement *muxer = NULL;
  GstElement *filesink = NULL;

  GstBus *bus = NULL;
  GMainLoop *loop = NULL;

  // Initialization
  if (!gst_init_check(NULL, NULL, &error)) {
    g_warning("gst_init failed: %s", error->message);
    goto error_gst_init;
  }

  // Parse options from command-line.
  while (arg < argc) {
    if ((strcmp(argv[arg], "-h") == 0) || (strcmp(argv[arg], "--help") == 0)) {
      g_message("\n%s\n", usage);
      status = 0;
      goto out_at_once;
    } else if (strcmp(argv[arg], "-c") == 0) {
      arg++;
      codec_str = argv[arg];
    } else if (strncmp(argv[arg], "-", 1) == 0) {
      // Unknown option.
      g_message("Unknown option: %s\n%s", argv[arg], usage);
      goto out_at_once;
    } else {
      // End of options.
      break;
    }
    arg++;
  }

  if (arg + 1 < argc) {
    g_warning("options specified after filename\n%s", usage);
    goto out_at_once;
  }
  // Parse filename.
  if (arg < argc) {
    filename = argv[arg];
    // Extract filename from path. Try both Windows and Linux style.
    gchar *pathname = g_strdup(filename);
    gchar *end_path_name_linux = strrchr(pathname, '/');
    gchar *end_path_name_win = strrchr(pathname, '\\');
    if (end_path_name_linux && end_path_name_win) {
      // If both / and \ exists in the full path one of them is not supposed to be there.
      g_error("Filename %s has invalid characters", filename);
    }
    if (end_path_name_linux) {
      *end_path_name_linux = '\0';
      outfilename = g_strdup_printf("%s/signed_%s", pathname, end_path_name_linux + 1);
    } else if (end_path_name_win) {
      *end_path_name_win = '\0';
      outfilename = g_strdup_printf("%s\\signed_%s", pathname, end_path_name_win + 1);
    } else {
      outfilename = g_strdup_printf("signed_%s", filename);
    }
    g_free(pathname);
    g_message(
        "\nThe result of signing '%s' will be written to '%s'.\n"
        "Private and public key stored at '%s'",
        filename, outfilename, PATH_TO_KEY_FILES);
  }

  if (!filename || !outfilename) {
    g_warning("no filename was specified\n%s", usage);
    goto out_at_once;
  }
  g_free(usage);
  usage = NULL;

  // Determine if file is a Matroska container (.mkv)
  if (strstr(filename, ".mkv")) {
    demux_str = "matroskademux";
    mux_str = "matroskamux";
  }
  // Create a main loop to run the application in.
  loop = g_main_loop_new(NULL, FALSE);
  if (!loop) {
    g_error("failed creating a main loop");
    goto error_loop;
  }

  // Create pipeline.
  pipeline = gst_pipeline_new(NULL);
  if (!pipeline) {
    g_error("failed creating an empty pipeline");
    goto error_pipeline;
  }
  // TODO: Add GstClock

  // Watch for messages on the pipeline's bus (note that this will only work like this
  // when a GLib main loop is running)
  bus = gst_pipeline_get_bus(GST_PIPELINE(pipeline));
  gst_bus_add_watch(bus, bus_call, loop);
  gst_object_unref(bus);

  // Create elements and populate the pipeline.
  mediasigning = gst_element_factory_make("signing", NULL);
  if (!mediasigning) {
    g_message(
        "The gstsigning element could not be found. Make sure it is installed "
        "correctly in $(libdir)/gstreamer-1.0/ or ~/.gstreamer-1.0/plugins/ or in your "
        "GST_PLUGIN_PATH, and that gst-inspect-1.0 lists it. If it does not, check "
        "with 'GST_DEBUG=*:2 gst-inspect-1.0' for the reason why it is not being "
        "loaded.");
    goto error_mediasigning;
  }
  gst_object_ref_sink(mediasigning);

  filesrc = gst_element_factory_make("filesrc", NULL);
  if (!filesrc) {
    g_message("Could not create 'filesrc'");
    goto error_filesrc;
  }
  gst_object_ref_sink(filesrc);

  demuxer = gst_element_factory_make(demux_str, NULL);
  if (!demuxer) {
    g_message("Could not create '%s'", demux_str);
    goto error_demuxer;
  }
  gst_object_ref_sink(demuxer);

  if (strcmp(codec_str, "h264") == 0) {
    parser = gst_element_factory_make("h264parse", NULL);
  } else {
    parser = gst_element_factory_make("h265parse", NULL);
  }
  if (!parser) {
    g_message("Could not create '%sparse'", codec_str);
    goto error_parser;
  }
  gst_object_ref_sink(parser);

  muxer = gst_element_factory_make(mux_str, NULL);
  if (!muxer) {
    g_message("Could not create '%s'", mux_str);
    goto error_muxer;
  }
  gst_object_ref_sink(muxer);

  filesink = gst_element_factory_make("filesink", NULL);
  if (!filesink) {
    g_message("Could not create 'filesink'");
    goto error_filesink;
  }
  gst_object_ref_sink(filesink);

  // Set file names locations of src and sink.
  g_object_set(G_OBJECT(filesrc), "location", filename, NULL);
  g_object_set(G_OBJECT(filesink), "location", outfilename, NULL);

  // Add all elements to the pipeline bin.
  gst_bin_add_many(
      GST_BIN(pipeline), filesrc, demuxer, parser, mediasigning, muxer, filesink, NULL);
  // Link everything together
  if (!gst_element_link(filesrc, demuxer)) {
    g_message("Failed to link the elements 'filesrc' and '%s'!", demux_str);
    goto error_link;
  }
  if (!gst_element_link_many(parser, mediasigning, muxer, filesink, NULL)) {
    g_message("Failed to link the elements '%sparse', 'signing', '%s' and 'filesink'!",
        codec_str, mux_str);
    goto error_link;
  }

  // Add a callback to link demuxer and parser when pads exist.
  g_signal_connect(demuxer, "pad-added", G_CALLBACK(pad_added_cb), parser);

  // Set playing state and start the main loop.
  if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE) {
    g_message("Failed to start up pipeline!");
    // Check if there is an error message with details on the bus.
    bus = gst_pipeline_get_bus(GST_PIPELINE(pipeline));
    GstMessage *msg = gst_bus_poll(bus, GST_MESSAGE_ERROR, 0);
    gst_object_unref(bus);
    bus = NULL;
    if (msg) {
      gst_message_parse_error(msg, &error, NULL);
      g_printerr("Failed to start up pipeline: %s", error->message);
      gst_message_unref(msg);
    } else {
      g_error("No message on the bus");
    }
    goto error_set_start_state;
  }

  g_main_loop_run(loop);

  if (gst_element_set_state(pipeline, GST_STATE_NULL) == GST_STATE_CHANGE_FAILURE) {
    g_message("Failed to stop pipeline!");
    // Check if there is an error message with details on the bus.
    bus = gst_pipeline_get_bus(GST_PIPELINE(pipeline));
    GstMessage *msg = gst_bus_poll(bus, GST_MESSAGE_ERROR, 0);
    gst_object_unref(bus);
    bus = NULL;
    if (msg) {
      gst_message_parse_error(msg, &error, NULL);
      g_printerr("Failed to stop pipeline: %s", error->message);
      gst_message_unref(msg);
    } else {
      g_error("No message on the bus");
    }
    goto error_set_stop_state;
  }

  status = 0;

  // End of session. Free objects.
error_set_stop_state:
  g_main_loop_quit(loop);
error_set_start_state:
error_link:
  gst_object_unref(filesink);
error_filesink:
  gst_object_unref(muxer);
error_muxer:
  gst_object_unref(parser);
error_parser:
  gst_object_unref(demuxer);
error_demuxer:
  gst_object_unref(filesrc);
error_filesrc:
  gst_object_unref(mediasigning);
error_mediasigning:
  gst_object_unref(pipeline);
error_pipeline:
  g_main_loop_unref(loop);
error_loop:
out_at_once:
  g_free(outfilename);
error_gst_init:
  if (error)
    g_error_free(error);
  g_free(usage);
  usage = NULL;
  gst_deinit();

  return status;
}
