/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsconnection-apple.c
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"
#include "glib.h"

#include "gtlsconnection-apple.h"
#include "gtlscertificate-apple.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gio/gio.h>
#include <glib/gi18n-lib.h>

#define TRANSFER_BUFFER_SIZE (64 * 1024)

typedef enum
{
  STATE_INIT,
  STATE_HANDSHAKING,
  STATE_READY,
  STATE_FAILED,
  STATE_CLOSED,
} ConnectionState;

typedef struct _StreamPump      StreamPump;
typedef struct _DatagramPump    DatagramPump;
typedef struct _BridgePump      BridgePump;
typedef struct _AppleBaseSource AppleBaseSource;

typedef struct
{
  nw_connection_t connection;
  dispatch_queue_t queue;

  GMutex state_mutex;
  GCond  state_cond;
  ConnectionState state;
  GError *fatal_error;

  gchar *negotiated_alpn;
  GTlsProtocolVersion protocol_version;
  gchar *ciphersuite_name;
  GTlsCertificateApple *peer_cert;

  GQueue  *rx_queue;
  gsize    rx_offset;
  gboolean rx_outstanding;
  gboolean rx_eof_pending;

  gboolean tx_in_flight;

  GSource *wakeup_source;

  sec_trust_t verify_trust;
  gboolean    verify_pending;
  gboolean    verify_accepted;
  GWeakRef   *weak_self;

  gboolean is_dtls;
  GIOStream *base_iostream;
  GInputStream *base_istream;
  GOutputStream *base_ostream;
  GDatagramBased *base_socket;
  gboolean base_input_pollable;
  gboolean base_output_pollable;
  GMainContext *bridge_context;
  GCancellable *io_cancellable;

  int bounce_fd;
  GSocket *bounce_socket;
  GInputStream *bounce_istream;
  GOutputStream *bounce_ostream;
  int public_listen_fd;
  gboolean public_endpoint_pending;
  nw_listener_t public_listener;

  BridgePump *bridge_pump_forward;
  BridgePump *bridge_pump_reverse;

  StreamPump *forward_stream_pump;
  StreamPump *reverse_stream_pump;

  DatagramPump *forward_datagram_pump;
  DatagramPump *reverse_datagram_pump;

  GMutex base_sources_mutex;
  GList *base_sources;
} GTlsConnectionApplePrivate;

struct _StreamPump
{
  gint ref_count;

  GMainContext *context;
  GCancellable *cancellable;
  GInputStream *source;
  GOutputStream *sink;
  gboolean source_pollable;
  gboolean sink_pollable;

  guint8 *buffer;
  gsize   buffer_capacity;
  gsize   buffer_length;
  gsize   buffer_offset;

  GSource *source_ready_source;
  GSource *sink_ready_source;
  gboolean async_read_in_flight;
  gboolean async_write_in_flight;
  gboolean stopped;
};

struct _DatagramPump
{
  gint ref_count;

  GMainContext *context;
  GCancellable *cancellable;
  GDatagramBased *source;
  GDatagramBased *sink;

  guint8 *buffer;
  gsize   buffer_capacity;
  gsize   pending_size;

  GSource *source_ready_source;
  GSource *sink_ready_source;
  gboolean stopped;
};

#ifdef GIO_APPLE_PUBLIC_API_ONLY
struct _BridgePump
{
  int                src_fd;
  int                dst_fd;
  gboolean           is_datagram;
  dispatch_queue_t   queue;
  dispatch_source_t  read_src;
  dispatch_source_t  write_src;
  guint8            *buffer;
  gsize              buffer_capacity;
  gsize              buffer_offset;
  gsize              buffer_length;
  gboolean           read_suspended;
  gboolean           stopped;
  gboolean           stopping;
  int                outstanding_sources;
};
#endif

struct _AppleBaseSource
{
  GSource              source;
  GTlsConnectionApple *tls;
  GIOCondition         condition;
  GMainContext        *attached_context;
};

static void                     g_tls_connection_apple_dispose           (GObject *object);
static void                     g_tls_connection_apple_finalize          (GObject *object);
static GTlsConnectionBaseStatus g_tls_connection_apple_handshake_thread_handshake
                                                                         (GTlsConnectionBase   *tls,
                                                                          gint64                timeout,
                                                                          GCancellable         *cancellable,
                                                                          GError              **error);
static GTlsCertificate *        g_tls_connection_apple_retrieve_peer_certificate
                                                                         (GTlsConnectionBase *tls,
                                                                          gboolean           *using_psk);
static GTlsCertificateFlags     g_tls_connection_apple_verify_chain      (GTlsConnectionBase       *tls,
                                                                          GTlsCertificate          *chain,
                                                                          const gchar              *purpose,
                                                                          GSocketConnectable       *identity,
                                                                          GTlsInteraction          *interaction,
                                                                          GTlsDatabaseVerifyFlags   flags,
                                                                          GCancellable             *cancellable,
                                                                          GError                  **error);
static void                     g_tls_connection_apple_complete_handshake
                                                                         (GTlsConnectionBase   *tls,
                                                                          gboolean              succeeded,
                                                                          gchar               **negotiated_protocol,
                                                                          GTlsProtocolVersion  *protocol_version,
                                                                          gchar               **ciphersuite_name,
                                                                          GError              **error);
static gboolean                 g_tls_connection_apple_is_session_resumed
                                                                         (GTlsConnectionBase *tls);
static GTlsConnectionBaseStatus g_tls_connection_apple_read_fn           (GTlsConnectionBase   *tls,
                                                                          void                 *buffer,
                                                                          gsize                 count,
                                                                          gint64                timeout,
                                                                          gssize               *nread,
                                                                          GCancellable         *cancellable,
                                                                          GError              **error);
static GTlsConnectionBaseStatus g_tls_connection_apple_read_message_fn   (GTlsConnectionBase   *tls,
                                                                          GInputVector         *vectors,
                                                                          guint                 num_vectors,
                                                                          gint64                timeout,
                                                                          gssize               *nread,
                                                                          GCancellable         *cancellable,
                                                                          GError              **error);
static GTlsConnectionBaseStatus g_tls_connection_apple_write_fn          (GTlsConnectionBase   *tls,
                                                                          const void           *buffer,
                                                                          gsize                 count,
                                                                          gint64                timeout,
                                                                          gssize               *nwrote,
                                                                          GCancellable         *cancellable,
                                                                          GError              **error);
static GTlsConnectionBaseStatus g_tls_connection_apple_write_message_fn  (GTlsConnectionBase   *tls,
                                                                          GOutputVector        *vectors,
                                                                          guint                 num_vectors,
                                                                          gint64                timeout,
                                                                          gssize               *nwrote,
                                                                          GCancellable         *cancellable,
                                                                          GError              **error);
static GTlsConnectionBaseStatus g_tls_connection_apple_close_fn          (GTlsConnectionBase   *tls,
                                                                          gint64                timeout,
                                                                          GCancellable         *cancellable,
                                                                          GError              **error);
static gboolean                 g_tls_connection_apple_base_check        (GTlsConnectionBase   *tls,
                                                                          GIOCondition          condition);
static GSource                 *g_tls_connection_apple_create_base_source
                                                                         (GTlsConnectionBase   *tls,
                                                                          GIOCondition          condition,
                                                                          GCancellable         *cancellable);

static gboolean drain_rx_queue_locked        (GTlsConnectionApplePrivate *priv,
                                              void                       *buffer,
                                              gsize                       count,
                                              gssize                     *nread);
static void     release_rx_head_chunk_locked (GTlsConnectionApplePrivate *priv);
static void     kick_receive_locked          (GTlsConnectionApple        *self);
static void     handle_receive_completion    (GTlsConnectionApple        *self,
                                              dispatch_data_t             content,
                                              nw_content_context_t        ctx,
                                              bool                        is_complete,
                                              nw_error_t                  nw_error);
static gboolean drain_rx_datagram_locked     (GTlsConnectionApplePrivate *priv,
                                              void                       *buffer,
                                              gsize                       count,
                                              gssize                     *nread);
static void     handle_send_completion       (GTlsConnectionApple        *self,
                                              nw_error_t                  nw_error);

static gboolean apple_base_source_prepare       (GSource *source, gint *timeout);
static gboolean apple_base_source_check         (GSource *source);
static gboolean apple_base_source_dispatch      (GSource *source, GSourceFunc callback, gpointer user_data);
static void     apple_base_source_dispose       (GSource *source);
static void     apple_base_source_finalize      (GSource *source);
static gboolean return_true                     (gpointer user_data);
static void     apple_base_source_cache_context (AppleBaseSource *s);

static int      setup_tls_bounce_transport   (GTlsConnectionApple *self,
                                              GError             **error);
static int      setup_dtls_bounce_transport  (GTlsConnectionApple *self,
                                              GError             **error);
static gboolean make_tcp_loopback_pair       (int     *out_apple_fd,
                                              int     *out_our_fd,
                                              GError **error);
static gboolean make_udp_loopback_pair       (int     *out_apple_fd,
                                              int     *out_our_fd,
                                              GError **error);

#ifdef GIO_APPLE_PUBLIC_API_ONLY
static gboolean setup_public_tls_endpoint           (GTlsConnectionApple  *self,
                                                     guint16              *out_port,
                                                     GError              **error);
static gboolean make_tcp_loopback_listener          (int     *out_listen_fd,
                                                     guint16 *out_port,
                                                     GError **error);
static gboolean setup_public_dtls_endpoint          (GTlsConnectionApple  *self,
                                                     guint16              *out_port,
                                                     GError              **error);
static gboolean make_udp_loopback_local             (int     *out_fd,
                                                     guint16 *out_port,
                                                     GError **error);

static void     detach_listener_rendezvous          (nw_listener_t    listener,
                                                     dispatch_queue_t queue);
static gboolean dial_loopback_tcp                   (guint16  port,
                                                     int     *out_fd,
                                                     GError **error);
static gboolean dial_loopback_udp                   (guint16  port,
                                                     int     *out_fd,
                                                     GError **error);

static gboolean start_public_bridge                 (GTlsConnectionApple  *self,
                                                     GError              **error);
static void     stop_public_bridge                  (GTlsConnectionApple  *self);
static gboolean extract_base_fd                     (GTlsConnectionApple  *self,
                                                     int                  *out_fd,
                                                     GError              **error);

static BridgePump *bridge_pump_new                  (int               src_fd,
                                                     int               dst_fd,
                                                     gboolean          is_datagram,
                                                     dispatch_queue_t  queue);
static void     bridge_pump_start                   (BridgePump *pump);
static void     bridge_pump_cancel                  (BridgePump *pump);
static void     bridge_pump_handle_readable         (BridgePump *pump);
static void     bridge_pump_drain                   (BridgePump *pump);
static void     bridge_pump_handle_writable         (BridgePump *pump);
static void     bridge_pump_handle_source_cancelled (BridgePump        *pump,
                                                     dispatch_source_t  src);
static void     bridge_pump_drain_pending           (BridgePump *pump);
static void     bridge_pump_free                    (BridgePump *pump);

static gboolean finalize_public_bridge              (GTlsConnectionApple  *self,
                                                     GError              **error);
static gboolean finalize_public_tls_bridge          (GTlsConnectionApple  *self,
                                                     GError              **error);
static gboolean finalize_public_dtls_bridge         (GTlsConnectionApple  *self,
                                                     GError              **error);
static gboolean wait_for_first_datagram             (int                   fd,
                                                     struct sockaddr_in   *out_peer,
                                                     GError              **error);
static gboolean adopt_bounce_fd                     (GTlsConnectionApple  *self,
                                                     int                   fd,
                                                     gboolean              wrap_as_iostream,
                                                     GError              **error);
#endif
static gboolean running_on_dispatch_queue (dispatch_queue_t queue);

static GTlsCertificateApple *wrap_peer_chain (sec_protocol_metadata_t metadata);

static void     publish_nw_state             (GTlsConnectionApple   *self,
                                              nw_connection_state_t  nw_state,
                                              nw_error_t             nw_error);
static void     capture_negotiated_metadata_locked
                                             (GTlsConnectionApple *self);
static GTlsProtocolVersion translate_protocol_version (tls_protocol_version_t version);
static gchar   *format_ciphersuite           (tls_ciphersuite_t suite);

#ifndef GIO_APPLE_PUBLIC_API_ONLY
static void     start_stream_bridge           (GTlsConnectionApple *self);
static void     stop_stream_bridge            (GTlsConnectionApple *self);
static StreamPump *stream_pump_new           (GMainContext   *context,
                                              GCancellable   *cancellable,
                                              GInputStream   *source,
                                              GOutputStream  *sink,
                                              gboolean        source_pollable,
                                              gboolean        sink_pollable,
                                              gsize           buffer_capacity);
static StreamPump *stream_pump_ref           (StreamPump *pump);
static void     stream_pump_unref            (StreamPump *pump);
static void     stream_pump_stop             (StreamPump *pump);
static void     stream_pump_schedule         (StreamPump *pump);
static gboolean stream_pump_drive            (gpointer user_data);
static gboolean stream_pump_on_source_ready  (GObject *stream, gpointer user_data);
static gboolean stream_pump_on_sink_ready    (GObject *stream, gpointer user_data);
static void     stream_pump_on_read_done     (GObject *source, GAsyncResult *result, gpointer user_data);
static void     stream_pump_on_write_done    (GObject *source, GAsyncResult *result, gpointer user_data);

static void     start_datagram_bridge        (GTlsConnectionApple *self);
static void     stop_datagram_bridge         (GTlsConnectionApple *self);
static DatagramPump *datagram_pump_new (GMainContext   *context,
                                              GCancellable   *cancellable,
                                              GDatagramBased *source,
                                              GDatagramBased *sink,
                                              gsize           buffer_capacity);
static DatagramPump *datagram_pump_ref (DatagramPump *pump);
static void     datagram_pump_unref          (DatagramPump *pump);
static void     datagram_pump_stop           (DatagramPump *pump);
static void     datagram_pump_schedule       (DatagramPump *pump);
static gboolean datagram_pump_drive          (gpointer user_data);
static gboolean datagram_pump_on_source_ready (GDatagramBased *datagram_based,
                                               GIOCondition    condition,
                                               gpointer        user_data);
static gboolean datagram_pump_on_sink_ready   (GDatagramBased *datagram_based,
                                               GIOCondition    condition,
                                               gpointer        user_data);
#endif

static GError  *error_from_nw_error          (nw_error_t   nw_error,
                                              const gchar *default_message);
static void     fail_locked                  (GTlsConnectionApplePrivate *priv,
                                              GError                     *take_error);
static void     wake_up_wakeup_source        (GTlsConnectionApplePrivate *priv);
static void     wake_up_base_sources         (GTlsConnectionApplePrivate *priv);
static gint64   deadline_from_timeout        (gint64 timeout_us);
static gboolean wait_for_progress_locked     (GTlsConnectionApplePrivate *priv,
                                              gint64                      deadline,
                                              GCancellable               *cancellable);
static GSource *wakeup_source_new            (void);
static gboolean on_wakeup_source_dispatch    (GSource *source, GSourceFunc callback, gpointer user_data);

G_DEFINE_ABSTRACT_TYPE_WITH_PRIVATE (GTlsConnectionApple, g_tls_connection_apple,
                                     G_TYPE_TLS_CONNECTION_BASE)

#define PRIV(self) ((GTlsConnectionApplePrivate *) g_tls_connection_apple_get_instance_private (self))

static const void *queue_marker_key = &queue_marker_key;

static GSourceFuncs apple_base_source_funcs =
{
  apple_base_source_prepare,
  apple_base_source_check,
  apple_base_source_dispatch,
  apple_base_source_finalize,
  NULL,
  NULL,
};

static void
g_tls_connection_apple_class_init (GTlsConnectionAppleClass *klass)
{
  GObjectClass            *object_class = G_OBJECT_CLASS (klass);
  GTlsConnectionBaseClass *base_class   = G_TLS_CONNECTION_BASE_CLASS (klass);

  object_class->dispose  = g_tls_connection_apple_dispose;
  object_class->finalize = g_tls_connection_apple_finalize;

  base_class->handshake_thread_handshake = g_tls_connection_apple_handshake_thread_handshake;
  base_class->retrieve_peer_certificate  = g_tls_connection_apple_retrieve_peer_certificate;
  base_class->verify_chain               = g_tls_connection_apple_verify_chain;
  base_class->complete_handshake         = g_tls_connection_apple_complete_handshake;
  base_class->is_session_resumed         = g_tls_connection_apple_is_session_resumed;
  base_class->read_fn                    = g_tls_connection_apple_read_fn;
  base_class->read_message_fn            = g_tls_connection_apple_read_message_fn;
  base_class->write_fn                   = g_tls_connection_apple_write_fn;
  base_class->write_message_fn           = g_tls_connection_apple_write_message_fn;
  base_class->close_fn                   = g_tls_connection_apple_close_fn;
  base_class->base_check                 = g_tls_connection_apple_base_check;
  base_class->create_base_source         = g_tls_connection_apple_create_base_source;
}

static void
g_tls_connection_apple_init (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  priv->queue = dispatch_queue_create ("gio-apple-tls", DISPATCH_QUEUE_SERIAL);
  dispatch_queue_set_specific (priv->queue, queue_marker_key, priv->queue, NULL);
  g_mutex_init (&priv->state_mutex);
  g_cond_init (&priv->state_cond);
  priv->state = STATE_INIT;
  priv->rx_queue = g_queue_new ();
  priv->wakeup_source = wakeup_source_new ();
  priv->bounce_fd = -1;
  priv->public_listen_fd = -1;
  g_mutex_init (&priv->base_sources_mutex);
}

static void
g_tls_connection_apple_dispose (GObject *object)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (object);
  GTlsConnectionApplePrivate *priv = PRIV (self);

  G_OBJECT_CLASS (g_tls_connection_apple_parent_class)->dispose (object);

  g_cancellable_cancel (priv->io_cancellable);

  if (priv->connection != NULL)
    nw_connection_cancel (priv->connection);

#ifdef GIO_APPLE_PUBLIC_API_ONLY
  stop_public_bridge (self);
#else
  stop_datagram_bridge (self);
  stop_stream_bridge (self);
#endif

  g_clear_object (&priv->bounce_ostream);
  g_clear_object (&priv->bounce_istream);
  g_clear_object (&priv->bounce_socket);

  if (priv->public_listen_fd >= 0)
    {
      close (priv->public_listen_fd);
      priv->public_listen_fd = -1;
    }

  if (priv->public_listener != NULL)
    {
      nw_listener_cancel (priv->public_listener);
      nw_release (priv->public_listener);
      priv->public_listener = NULL;
    }

  g_clear_object (&priv->io_cancellable);
  g_clear_pointer (&priv->bridge_context, g_main_context_unref);
  g_clear_object (&priv->base_socket);
  g_clear_object (&priv->base_iostream);

  g_clear_pointer (&priv->verify_trust, nw_release);
  g_clear_object (&priv->peer_cert);
  g_clear_pointer (&priv->connection, nw_release);
}

static void
g_tls_connection_apple_finalize (GObject *object)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (object);
  GTlsConnectionApplePrivate *priv = PRIV (self);

  g_mutex_clear (&priv->base_sources_mutex);

  g_clear_pointer (&priv->wakeup_source, g_source_unref);

  while (!g_queue_is_empty (priv->rx_queue))
    release_rx_head_chunk_locked (priv);
  g_clear_pointer (&priv->rx_queue, g_queue_free);

  g_free (priv->ciphersuite_name);
  g_free (priv->negotiated_alpn);
  g_clear_error (&priv->fatal_error);

  g_cond_clear (&priv->state_cond);
  g_mutex_clear (&priv->state_mutex);

  g_clear_pointer (&priv->queue, dispatch_release);

  G_OBJECT_CLASS (g_tls_connection_apple_parent_class)->finalize (object);
}

static GTlsConnectionBaseStatus
g_tls_connection_apple_handshake_thread_handshake (GTlsConnectionBase   *tls,
                                                   gint64                timeout,
                                                   GCancellable         *cancellable,
                                                   GError              **error)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gint64 deadline = deadline_from_timeout (timeout);
  GTlsConnectionBaseStatus status;

  if (!priv->connection)
    {
      GTlsConnectionAppleClass *klass = G_TLS_CONNECTION_APPLE_GET_CLASS (self);
      if (klass->start_handshake == NULL || !klass->start_handshake (self, error))
        return G_TLS_CONNECTION_BASE_ERROR;
    }

  g_mutex_lock (&priv->state_mutex);

  while (priv->state == STATE_INIT || priv->state == STATE_HANDSHAKING)
    {
      if (priv->verify_pending)
        {
          gboolean accepted;

          g_mutex_unlock (&priv->state_mutex);
          accepted = g_tls_connection_base_handshake_thread_verify_certificate (
              G_TLS_CONNECTION_BASE (tls));
          g_mutex_lock (&priv->state_mutex);

          priv->verify_accepted = accepted;
          priv->verify_pending = FALSE;
          g_clear_pointer (&priv->verify_trust, nw_release);
          if (!accepted)
            fail_locked (priv,
                g_error_new_literal (G_TLS_ERROR, G_TLS_ERROR_BAD_CERTIFICATE,
                                     _("Unacceptable TLS certificate")));
          g_cond_broadcast (&priv->state_cond);
          continue;
        }

      if (!wait_for_progress_locked (priv, deadline, cancellable))
        {
          if (priv->verify_pending)
            {
              priv->verify_accepted = FALSE;
              priv->verify_pending = FALSE;
              g_cond_broadcast (&priv->state_cond);
            }
          g_mutex_unlock (&priv->state_mutex);
          if (g_cancellable_set_error_if_cancelled (cancellable, error))
            return G_TLS_CONNECTION_BASE_ERROR;
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                               _("TLS handshake timed out"));
          return G_TLS_CONNECTION_BASE_TIMED_OUT;
        }
    }

  if (priv->state == STATE_READY)
    {
      status = G_TLS_CONNECTION_BASE_OK;
    }
  else
    {
      if (priv->fatal_error)
        g_propagate_error (error, g_error_copy (priv->fatal_error));
      else
        g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                             _("TLS handshake failed"));
      status = G_TLS_CONNECTION_BASE_ERROR;
    }

  g_mutex_unlock (&priv->state_mutex);
  return status;
}

static GTlsCertificate *
g_tls_connection_apple_retrieve_peer_certificate (GTlsConnectionBase *tls,
                                                  gboolean           *using_psk)
{
  GTlsConnectionApplePrivate *priv = PRIV (G_TLS_CONNECTION_APPLE (tls));
  GTlsCertificate *peer;

  if (using_psk)
    *using_psk = FALSE;

  g_mutex_lock (&priv->state_mutex);
  peer = priv->peer_cert ? g_object_ref (G_TLS_CERTIFICATE (priv->peer_cert)) : NULL;
  g_mutex_unlock (&priv->state_mutex);
  return peer;
}

static GTlsCertificateFlags
g_tls_connection_apple_verify_chain (GTlsConnectionBase       *tls,
                                     GTlsCertificate          *chain,
                                     const gchar              *purpose,
                                     GSocketConnectable       *identity,
                                     GTlsInteraction          *interaction,
                                     GTlsDatabaseVerifyFlags   flags,
                                     GCancellable             *cancellable,
                                     GError                  **error)
{
  GTlsDatabase *database;

  database = g_tls_connection_get_database (G_TLS_CONNECTION (tls));
  if (!database)
    return G_TLS_CERTIFICATE_UNKNOWN_CA;

  return g_tls_database_verify_chain (database, chain, purpose, identity,
                                      interaction, flags, cancellable, error);
}

static void
g_tls_connection_apple_complete_handshake (GTlsConnectionBase   *tls,
                                           gboolean              succeeded,
                                           gchar               **negotiated_protocol,
                                           GTlsProtocolVersion  *protocol_version,
                                           gchar               **ciphersuite_name,
                                           GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (G_TLS_CONNECTION_APPLE (tls));

  if (!succeeded)
    return;

  g_mutex_lock (&priv->state_mutex);
  if (negotiated_protocol)
    *negotiated_protocol = g_strdup (priv->negotiated_alpn);
  if (protocol_version)
    *protocol_version = priv->protocol_version;
  if (ciphersuite_name)
    *ciphersuite_name = g_strdup (priv->ciphersuite_name);
  g_mutex_unlock (&priv->state_mutex);
}

static gboolean
g_tls_connection_apple_is_session_resumed (GTlsConnectionBase *tls)
{
  return FALSE;
}

static GTlsConnectionBaseStatus
g_tls_connection_apple_read_fn (GTlsConnectionBase   *tls,
                                void                 *buffer,
                                gsize                 count,
                                gint64                timeout,
                                gssize               *nread,
                                GCancellable         *cancellable,
                                GError              **error)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gint64 deadline = deadline_from_timeout (timeout);

  *nread = 0;

  g_mutex_lock (&priv->state_mutex);

  for (;;)
    {
      if (drain_rx_queue_locked (priv, buffer, count, nread))
        {
          kick_receive_locked (self);
          g_mutex_unlock (&priv->state_mutex);
          return G_TLS_CONNECTION_BASE_OK;
        }

      if (priv->fatal_error)
        {
          g_propagate_error (error, g_error_copy (priv->fatal_error));
          g_mutex_unlock (&priv->state_mutex);
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (priv->rx_eof_pending ||
          priv->state == STATE_CLOSED ||
          priv->state == STATE_FAILED)
        {
          g_mutex_unlock (&priv->state_mutex);
          return G_TLS_CONNECTION_BASE_OK;
        }

      kick_receive_locked (self);

      if (timeout == 0)
        {
          g_mutex_unlock (&priv->state_mutex);
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                               _("Operation would block"));
          return G_TLS_CONNECTION_BASE_WOULD_BLOCK;
        }

      if (!wait_for_progress_locked (priv, deadline, cancellable))
        {
          g_mutex_unlock (&priv->state_mutex);
          if (g_cancellable_set_error_if_cancelled (cancellable, error))
            return G_TLS_CONNECTION_BASE_ERROR;
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                               _("Read timed out"));
          return G_TLS_CONNECTION_BASE_TIMED_OUT;
        }
    }
}

static gboolean
drain_rx_queue_locked (GTlsConnectionApplePrivate *priv,
                       void                       *buffer,
                       gsize                       count,
                       gssize                     *nread)
{
  guchar *out = buffer;

  while (count > 0 && priv->rx_queue->head)
    {
      dispatch_data_t head = (dispatch_data_t) priv->rx_queue->head->data;
      size_t head_len = dispatch_data_get_size (head);
      size_t remaining_in_head = head_len - priv->rx_offset;
      size_t take = remaining_in_head < count ? remaining_in_head : count;

      dispatch_data_t slice = dispatch_data_create_subrange (head, priv->rx_offset, take);
      __block size_t copied = 0;
      dispatch_data_apply (slice, ^bool (dispatch_data_t region,
                                         size_t offset,
                                         const void *bytes,
                                         size_t size) {
        memcpy (out + copied, bytes, size);
        copied += size;
        return true;
      });
      dispatch_release (slice);

      priv->rx_offset += take;
      out += take;
      *nread += take;
      count -= take;

      if (priv->rx_offset == head_len)
        release_rx_head_chunk_locked (priv);
    }

  return *nread > 0;
}

static void
release_rx_head_chunk_locked (GTlsConnectionApplePrivate *priv)
{
  dispatch_data_t head = (dispatch_data_t) g_queue_pop_head (priv->rx_queue);
  dispatch_release (head);
  priv->rx_offset = 0;
}

static void
kick_receive_locked (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  GTlsConnectionApple *captured_self;

  if (priv->rx_outstanding || priv->rx_eof_pending)
    return;
  if (priv->state != STATE_READY)
    return;
  if (priv->rx_queue->length > 0)
    return;

  priv->rx_outstanding = TRUE;

  captured_self = g_object_ref (self);
  nw_connection_receive (priv->connection, 1, TRANSFER_BUFFER_SIZE,
      ^(dispatch_data_t content,
        nw_content_context_t ctx,
        bool is_complete,
        nw_error_t nw_error) {
        handle_receive_completion (captured_self, content, ctx, is_complete, nw_error);
        g_object_unref (captured_self);
      });
}

static void
handle_receive_completion (GTlsConnectionApple *self,
                           dispatch_data_t      content,
                           nw_content_context_t ctx,
                           bool                 is_complete,
                           nw_error_t           nw_error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  g_mutex_lock (&priv->state_mutex);
  priv->rx_outstanding = FALSE;

  if (content && dispatch_data_get_size (content) > 0)
    {
      dispatch_retain (content);
      g_queue_push_tail (priv->rx_queue, (gpointer) content);
    }

  if (is_complete && ctx != NULL && nw_content_context_get_is_final (ctx))
    priv->rx_eof_pending = TRUE;

  if (nw_error)
    fail_locked (priv, error_from_nw_error (nw_error, _("TLS read failed")));

  g_cond_broadcast (&priv->state_cond);
  g_mutex_unlock (&priv->state_mutex);
  wake_up_wakeup_source (priv);
  wake_up_base_sources (priv);
}

static GTlsConnectionBaseStatus
g_tls_connection_apple_read_message_fn (GTlsConnectionBase  *tls,
                                        GInputVector        *vectors,
                                        guint                num_vectors,
                                        gint64               timeout,
                                        gssize              *nread,
                                        GCancellable        *cancellable,
                                        GError             **error)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gint64 deadline = deadline_from_timeout (timeout);
  gsize capacity = 0;
  guint8 *staging;
  gssize datagram_size = 0;
  gsize copied = 0;
  guint i;

  *nread = 0;

  for (i = 0; i < num_vectors; i++)
    capacity += vectors[i].size;
  if (capacity == 0)
    return G_TLS_CONNECTION_BASE_OK;

  if (!priv->is_dtls)
    {
      GTlsConnectionBaseStatus status;

      staging = g_malloc (capacity);
      status = g_tls_connection_apple_read_fn (tls, staging, capacity, timeout,
                                               &datagram_size, cancellable, error);
      if (status != G_TLS_CONNECTION_BASE_OK)
        {
          g_free (staging);
          return status;
        }

      for (i = 0; i < num_vectors && copied < (gsize) datagram_size; i++)
        {
          GInputVector *vec = &vectors[i];
          gsize take = MIN (vec->size, (gsize) datagram_size - copied);

          memcpy (vec->buffer, staging + copied, take);
          copied += take;
        }

      g_free (staging);
      *nread = copied;
      return status;
    }

  staging = g_malloc (capacity);

  g_mutex_lock (&priv->state_mutex);

  for (;;)
    {
      if (drain_rx_datagram_locked (priv, staging, capacity, &datagram_size))
        {
          kick_receive_locked (self);
          g_mutex_unlock (&priv->state_mutex);
          break;
        }

      if (priv->fatal_error)
        {
          g_propagate_error (error, g_error_copy (priv->fatal_error));
          g_mutex_unlock (&priv->state_mutex);
          g_free (staging);
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (priv->rx_eof_pending ||
          priv->state == STATE_CLOSED ||
          priv->state == STATE_FAILED)
        {
          g_mutex_unlock (&priv->state_mutex);
          g_free (staging);
          return G_TLS_CONNECTION_BASE_OK;
        }

      kick_receive_locked (self);

      if (timeout == 0)
        {
          g_mutex_unlock (&priv->state_mutex);
          g_free (staging);
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                               _("Operation would block"));
          return G_TLS_CONNECTION_BASE_WOULD_BLOCK;
        }

      if (!wait_for_progress_locked (priv, deadline, cancellable))
        {
          g_mutex_unlock (&priv->state_mutex);
          g_free (staging);
          if (g_cancellable_set_error_if_cancelled (cancellable, error))
            return G_TLS_CONNECTION_BASE_ERROR;
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                               _("Read timed out"));
          return G_TLS_CONNECTION_BASE_TIMED_OUT;
        }
    }

  for (i = 0; i < num_vectors && copied < (gsize) datagram_size; i++)
    {
      GInputVector *vec = &vectors[i];
      gsize take = MIN (vec->size, (gsize) datagram_size - copied);

      memcpy (vec->buffer, staging + copied, take);
      copied += take;
    }

  g_free (staging);
  *nread = copied;
  return G_TLS_CONNECTION_BASE_OK;
}

static gboolean
drain_rx_datagram_locked (GTlsConnectionApplePrivate *priv,
                          void                       *buffer,
                          gsize                       count,
                          gssize                     *nread)
{
  dispatch_data_t head;
  size_t head_len, take;
  guchar *out = buffer;

  if (priv->rx_queue->head == NULL)
    return FALSE;

  head = (dispatch_data_t) priv->rx_queue->head->data;
  head_len = dispatch_data_get_size (head);
  take = head_len < count ? head_len : count;

  if (take > 0)
    {
      dispatch_data_t slice = dispatch_data_create_subrange (head, 0, take);
      __block size_t copied = 0;
      dispatch_data_apply (slice, ^bool (dispatch_data_t region,
                                         size_t offset,
                                         const void *bytes,
                                         size_t size) {
        memcpy (out + copied, bytes, size);
        copied += size;
        return true;
      });
      dispatch_release (slice);
    }

  *nread = take;
  release_rx_head_chunk_locked (priv);
  return TRUE;
}

static GTlsConnectionBaseStatus
g_tls_connection_apple_write_fn (GTlsConnectionBase   *tls,
                                 const void           *buffer,
                                 gsize                 count,
                                 gint64                timeout,
                                 gssize               *nwrote,
                                 GCancellable         *cancellable,
                                 GError              **error)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gint64 deadline = deadline_from_timeout (timeout);
  dispatch_data_t payload;
  GTlsConnectionApple *captured_self;

  *nwrote = 0;

  g_mutex_lock (&priv->state_mutex);

  while (priv->tx_in_flight)
    {
      if (priv->state == STATE_FAILED && priv->fatal_error)
        {
          g_propagate_error (error, g_error_copy (priv->fatal_error));
          g_mutex_unlock (&priv->state_mutex);
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (timeout == 0)
        {
          g_mutex_unlock (&priv->state_mutex);
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                               _("Operation would block"));
          return G_TLS_CONNECTION_BASE_WOULD_BLOCK;
        }

      if (!wait_for_progress_locked (priv, deadline, cancellable))
        {
          g_mutex_unlock (&priv->state_mutex);
          if (g_cancellable_set_error_if_cancelled (cancellable, error))
            return G_TLS_CONNECTION_BASE_ERROR;
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                               _("Write timed out"));
          return G_TLS_CONNECTION_BASE_TIMED_OUT;
        }
    }

  if (priv->state != STATE_READY)
    {
      if (priv->fatal_error)
        g_propagate_error (error, g_error_copy (priv->fatal_error));
      else
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
                             _("TLS connection is not open"));
      g_mutex_unlock (&priv->state_mutex);
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  priv->tx_in_flight = TRUE;

  payload = dispatch_data_create (buffer, count, priv->queue,
                                  DISPATCH_DATA_DESTRUCTOR_DEFAULT);
  captured_self = g_object_ref (self);
  nw_connection_send (priv->connection, payload, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
                      false, ^(nw_error_t nw_error) {
    handle_send_completion (captured_self, nw_error);
    g_object_unref (captured_self);
  });
  dispatch_release (payload);

  *nwrote = count;
  g_mutex_unlock (&priv->state_mutex);
  return G_TLS_CONNECTION_BASE_OK;
}

static void
handle_send_completion (GTlsConnectionApple *self,
                        nw_error_t           nw_error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  g_mutex_lock (&priv->state_mutex);
  priv->tx_in_flight = FALSE;

  if (nw_error)
    fail_locked (priv, error_from_nw_error (nw_error, _("TLS write failed")));

  g_cond_broadcast (&priv->state_cond);
  g_mutex_unlock (&priv->state_mutex);
  wake_up_wakeup_source (priv);
  wake_up_base_sources (priv);
}

static GTlsConnectionBaseStatus
g_tls_connection_apple_write_message_fn (GTlsConnectionBase  *tls,
                                         GOutputVector       *vectors,
                                         guint                num_vectors,
                                         gint64               timeout,
                                         gssize              *nwrote,
                                         GCancellable        *cancellable,
                                         GError             **error)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gint64 deadline = deadline_from_timeout (timeout);
  gsize total = 0;
  guint8 *payload_buf;
  gsize offset = 0;
  dispatch_data_t payload;
  GTlsConnectionApple *captured_self;
  guint i;

  *nwrote = 0;

  for (i = 0; i < num_vectors; i++)
    total += vectors[i].size;

  if (total == 0)
    return G_TLS_CONNECTION_BASE_OK;

  payload_buf = g_malloc (total);
  for (i = 0; i < num_vectors; i++)
    {
      GOutputVector *vec = &vectors[i];
      memcpy (payload_buf + offset, vec->buffer, vec->size);
      offset += vec->size;
    }

  g_mutex_lock (&priv->state_mutex);

  while (priv->tx_in_flight)
    {
      if (priv->state == STATE_FAILED && priv->fatal_error)
        {
          g_propagate_error (error, g_error_copy (priv->fatal_error));
          g_mutex_unlock (&priv->state_mutex);
          g_free (payload_buf);
          return G_TLS_CONNECTION_BASE_ERROR;
        }

      if (timeout == 0)
        {
          g_mutex_unlock (&priv->state_mutex);
          g_free (payload_buf);
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK,
                               _("Operation would block"));
          return G_TLS_CONNECTION_BASE_WOULD_BLOCK;
        }

      if (!wait_for_progress_locked (priv, deadline, cancellable))
        {
          g_mutex_unlock (&priv->state_mutex);
          g_free (payload_buf);
          if (g_cancellable_set_error_if_cancelled (cancellable, error))
            return G_TLS_CONNECTION_BASE_ERROR;
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                               _("Write timed out"));
          return G_TLS_CONNECTION_BASE_TIMED_OUT;
        }
    }

  if (priv->state != STATE_READY)
    {
      if (priv->fatal_error)
        g_propagate_error (error, g_error_copy (priv->fatal_error));
      else
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CONNECTION_CLOSED,
                             _("TLS connection is not open"));
      g_mutex_unlock (&priv->state_mutex);
      g_free (payload_buf);
      return G_TLS_CONNECTION_BASE_ERROR;
    }

  priv->tx_in_flight = TRUE;

  payload = dispatch_data_create (payload_buf, total, priv->queue,
                                  ^{ g_free (payload_buf); });
  captured_self = g_object_ref (self);
  nw_connection_send (priv->connection, payload, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
                      true, ^(nw_error_t nw_error) {
    handle_send_completion (captured_self, nw_error);
    g_object_unref (captured_self);
  });
  dispatch_release (payload);

  *nwrote = total;
  g_mutex_unlock (&priv->state_mutex);
  return G_TLS_CONNECTION_BASE_OK;
}

static GTlsConnectionBaseStatus
g_tls_connection_apple_close_fn (GTlsConnectionBase   *tls,
                                 gint64                timeout,
                                 GCancellable         *cancellable,
                                 GError              **error)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gint64 deadline = deadline_from_timeout (timeout);
  gboolean on_queue = running_on_dispatch_queue (priv->queue);

  g_mutex_lock (&priv->state_mutex);

  while (priv->tx_in_flight && priv->state == STATE_READY)
    {
      if (!wait_for_progress_locked (priv, deadline, cancellable))
        break;
    }

  if (!on_queue && priv->connection != NULL && priv->state == STATE_READY)
    {
      nw_connection_t connection = priv->connection;
      dispatch_semaphore_t flush_sem = dispatch_semaphore_create (0);
      dispatch_retain (flush_sem);
      nw_connection_send (connection, NULL, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
          ^(nw_error_t error) {
            dispatch_semaphore_signal (flush_sem);
            dispatch_release (flush_sem);
          });
      g_mutex_unlock (&priv->state_mutex);
      if (dispatch_semaphore_wait (flush_sem,
              dispatch_time (DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC)) != 0)
        {
          nw_connection_cancel (connection);
          dispatch_semaphore_wait (flush_sem, DISPATCH_TIME_FOREVER);
        }
      dispatch_release (flush_sem);
      g_mutex_lock (&priv->state_mutex);
    }

  if (priv->connection != NULL && priv->state != STATE_CLOSED)
    nw_connection_cancel (priv->connection);

  if (!on_queue)
    {
      gint64 cancel_deadline = g_get_monotonic_time () + 500 * G_TIME_SPAN_MILLISECOND;

      while (priv->state != STATE_CLOSED && priv->state != STATE_FAILED)
        {
          if (!g_cond_wait_until (&priv->state_cond, &priv->state_mutex, cancel_deadline))
            break;
        }
    }

  priv->state = STATE_CLOSED;
  g_cond_broadcast (&priv->state_cond);
  g_mutex_unlock (&priv->state_mutex);

  g_clear_pointer (&priv->connection, nw_release);

  g_cancellable_cancel (priv->io_cancellable);
#ifdef GIO_APPLE_PUBLIC_API_ONLY
  stop_public_bridge (self);
#else
  stop_stream_bridge (self);
  stop_datagram_bridge (self);
#endif
  wake_up_wakeup_source (priv);
  wake_up_base_sources (priv);

  return G_TLS_CONNECTION_BASE_OK;
}

static gboolean
g_tls_connection_apple_base_check (GTlsConnectionBase *tls,
                                   GIOCondition        condition)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gboolean ready = FALSE;

  g_mutex_lock (&priv->state_mutex);

  if (condition & G_IO_IN)
    ready = priv->rx_queue->length > 0 ||
            priv->rx_eof_pending ||
            priv->state == STATE_FAILED ||
            priv->state == STATE_CLOSED;
  else if (condition & G_IO_OUT)
    ready = (priv->state == STATE_READY && !priv->tx_in_flight) ||
            priv->state == STATE_FAILED ||
            priv->state == STATE_CLOSED;

  g_mutex_unlock (&priv->state_mutex);
  return ready;
}

static GSource *
g_tls_connection_apple_create_base_source (GTlsConnectionBase *tls,
                                           GIOCondition        condition,
                                           GCancellable       *cancellable)
{
  GTlsConnectionApple *self = G_TLS_CONNECTION_APPLE (tls);
  GTlsConnectionApplePrivate *priv = PRIV (self);
  GSource *source;
  AppleBaseSource *s;

  source = g_source_new (&apple_base_source_funcs, sizeof (AppleBaseSource));
  g_source_set_static_name (source, "GTlsConnectionApple base source");
  g_source_set_dispose_function (source, apple_base_source_dispose);
  s = (AppleBaseSource *) source;
  s->tls = g_object_ref (self);
  s->condition = condition;

  g_mutex_lock (&priv->base_sources_mutex);
  priv->base_sources = g_list_prepend (priv->base_sources, s);
  g_mutex_unlock (&priv->base_sources_mutex);

  if (cancellable != NULL)
    {
      GSource *cancellable_source = g_cancellable_source_new (cancellable);
      g_source_set_callback (cancellable_source, (GSourceFunc) return_true, NULL, NULL);
      g_source_add_child_source (source, cancellable_source);
      g_source_unref (cancellable_source);
    }

  return source;
}

static gboolean
apple_base_source_prepare (GSource *source, gint *timeout)
{
  AppleBaseSource *s = (AppleBaseSource *) source;
  gboolean ready;

  apple_base_source_cache_context (s);

  ready = g_tls_connection_apple_base_check (G_TLS_CONNECTION_BASE (s->tls), s->condition);
  *timeout = ready ? 0 : -1;
  return ready;
}

static gboolean
apple_base_source_check (GSource *source)
{
  AppleBaseSource *s = (AppleBaseSource *) source;

  apple_base_source_cache_context (s);

  return g_tls_connection_apple_base_check (G_TLS_CONNECTION_BASE (s->tls), s->condition);
}

static gboolean
apple_base_source_dispatch (GSource *source, GSourceFunc callback, gpointer user_data)
{
  if (callback)
    return callback (user_data);
  return G_SOURCE_CONTINUE;
}

static void
apple_base_source_dispose (GSource *source)
{
  AppleBaseSource *s = (AppleBaseSource *) source;
  GTlsConnectionApplePrivate *priv = PRIV (s->tls);

  g_mutex_lock (&priv->base_sources_mutex);
  priv->base_sources = g_list_remove (priv->base_sources, s);
  g_clear_pointer (&s->attached_context, g_main_context_unref);
  g_mutex_unlock (&priv->base_sources_mutex);
}

static void
apple_base_source_finalize (GSource *source)
{
  AppleBaseSource *s = (AppleBaseSource *) source;

  g_object_unref (s->tls);
}

static gboolean
return_true (gpointer user_data)
{
  return G_SOURCE_CONTINUE;
}

static void
apple_base_source_cache_context (AppleBaseSource *s)
{
  GTlsConnectionApplePrivate *priv = PRIV (s->tls);
  GMainContext *ctx;

  ctx = g_source_get_context (&s->source);
  if (ctx == NULL)
    return;

  g_mutex_lock (&priv->base_sources_mutex);
  if (s->attached_context == NULL)
    s->attached_context = g_main_context_ref (ctx);
  g_mutex_unlock (&priv->base_sources_mutex);
}

gboolean
g_tls_connection_apple_bind_base_iostream (GTlsConnectionApple *self,
                                           GIOStream           *base,
                                           GError             **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  GInputStream *input;
  GOutputStream *output;

  input = g_io_stream_get_input_stream (base);
  output = g_io_stream_get_output_stream (base);

  priv->is_dtls = FALSE;
  priv->base_iostream = g_object_ref (base);
  priv->base_istream = input;
  priv->base_ostream = output;
  priv->base_input_pollable =
      G_IS_POLLABLE_INPUT_STREAM (input) &&
      g_pollable_input_stream_can_poll (G_POLLABLE_INPUT_STREAM (input));
  priv->base_output_pollable =
      G_IS_POLLABLE_OUTPUT_STREAM (output) &&
      g_pollable_output_stream_can_poll (G_POLLABLE_OUTPUT_STREAM (output));
  priv->io_cancellable = g_cancellable_new ();

  return TRUE;
}

gboolean
g_tls_connection_apple_bind_base_socket (GTlsConnectionApple *self,
                                         GDatagramBased      *base,
                                         GError             **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  priv->is_dtls = TRUE;
  priv->base_socket = g_object_ref (base);
  priv->io_cancellable = g_cancellable_new ();

  return TRUE;
}

int
g_tls_connection_apple_setup_bounce_transport (GTlsConnectionApple *self,
                                               GError             **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  return priv->is_dtls
      ? setup_dtls_bounce_transport (self, error)
      : setup_tls_bounce_transport (self, error);
}

static int
setup_tls_bounce_transport (GTlsConnectionApple *self,
                            GError             **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  int apple_fd = -1;
  int our_fd = -1;
  GSocket *bounce_socket = NULL;
  GSocketConnection *bounce_connection = NULL;

  if (G_IS_SOCKET_CONNECTION (priv->base_iostream))
    {
      GSocket *sock = g_socket_connection_get_socket (G_SOCKET_CONNECTION (priv->base_iostream));
      int dup_fd = dup (g_socket_get_fd (sock));
      if (dup_fd < 0)
        {
          g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                       "dup base socket: %s", g_strerror (errno));
          return -1;
        }
      return dup_fd;
    }

  if (!make_tcp_loopback_pair (&apple_fd, &our_fd, error))
    return -1;

  bounce_socket = g_socket_new_from_fd (our_fd, error);
  if (!bounce_socket)
    {
      close (apple_fd);
      close (our_fd);
      return -1;
    }
  g_socket_set_blocking (bounce_socket, FALSE);

  bounce_connection = g_socket_connection_factory_create_connection (bounce_socket);

  priv->bounce_fd = our_fd;
  priv->bounce_socket = bounce_socket;
  priv->bounce_istream = g_object_ref (g_io_stream_get_input_stream (G_IO_STREAM (bounce_connection)));
  priv->bounce_ostream = g_object_ref (g_io_stream_get_output_stream (G_IO_STREAM (bounce_connection)));
  g_object_unref (bounce_connection);

  return apple_fd;
}

static gboolean
make_tcp_loopback_pair (int     *out_apple_fd,
                        int     *out_our_fd,
                        GError **error)
{
  int listen_fd = -1, c_fd = -1, s_fd = -1;
  struct sockaddr_in addr = { 0 };
  socklen_t addr_len = sizeof addr;

  listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0)
    goto syscall_fail;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (listen_fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    goto syscall_fail;
  if (getsockname (listen_fd, (struct sockaddr *) &addr, &addr_len) < 0)
    goto syscall_fail;
  if (listen (listen_fd, 1) < 0)
    goto syscall_fail;

  c_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (c_fd < 0)
    goto syscall_fail;
  if (connect (c_fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    goto syscall_fail;

  s_fd = accept (listen_fd, NULL, NULL);
  if (s_fd < 0)
    goto syscall_fail;

  close (listen_fd);
  *out_apple_fd = s_fd;
  *out_our_fd = c_fd;
  return TRUE;

syscall_fail:
  {
    int saved = errno;
    if (listen_fd >= 0) close (listen_fd);
    if (c_fd >= 0) close (c_fd);
    if (s_fd >= 0) close (s_fd);
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                 "TCP loopback pair: %s", g_strerror (saved));
    return FALSE;
  }
}

static int
setup_dtls_bounce_transport (GTlsConnectionApple *self,
                             GError             **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  int apple_fd = -1;
  int our_fd = -1;

  if (G_IS_SOCKET (priv->base_socket) &&
      g_socket_get_socket_type (G_SOCKET (priv->base_socket)) == G_SOCKET_TYPE_DATAGRAM)
    {
      int dup_fd = dup (g_socket_get_fd (G_SOCKET (priv->base_socket)));
      if (dup_fd < 0)
        {
          g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                       "dup base datagram socket: %s", g_strerror (errno));
          return -1;
        }
      return dup_fd;
    }

  if (!make_udp_loopback_pair (&apple_fd, &our_fd, error))
    return -1;

  priv->bounce_fd = our_fd;
  priv->bounce_socket = g_socket_new_from_fd (our_fd, error);
  if (!priv->bounce_socket)
    {
      close (apple_fd);
      close (our_fd);
      priv->bounce_fd = -1;
      return -1;
    }
  g_socket_set_blocking (priv->bounce_socket, FALSE);

  return apple_fd;
}

static gboolean
make_udp_loopback_pair (int     *out_apple_fd,
                        int     *out_our_fd,
                        GError **error)
{
  int a_fd = -1, b_fd = -1;
  struct sockaddr_in a_addr = { 0 }, b_addr = { 0 };
  socklen_t len;

  a_fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (a_fd < 0)
    goto syscall_fail;
  b_fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (b_fd < 0)
    goto syscall_fail;

  a_addr.sin_family = AF_INET;
  a_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (a_fd, (struct sockaddr *) &a_addr, sizeof a_addr) < 0)
    goto syscall_fail;

  b_addr.sin_family = AF_INET;
  b_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (bind (b_fd, (struct sockaddr *) &b_addr, sizeof b_addr) < 0)
    goto syscall_fail;

  len = sizeof a_addr;
  if (getsockname (a_fd, (struct sockaddr *) &a_addr, &len) < 0)
    goto syscall_fail;
  len = sizeof b_addr;
  if (getsockname (b_fd, (struct sockaddr *) &b_addr, &len) < 0)
    goto syscall_fail;

  if (connect (a_fd, (struct sockaddr *) &b_addr, sizeof b_addr) < 0)
    goto syscall_fail;
  if (connect (b_fd, (struct sockaddr *) &a_addr, sizeof a_addr) < 0)
    goto syscall_fail;

  *out_apple_fd = a_fd;
  *out_our_fd = b_fd;
  return TRUE;

syscall_fail:
  {
    int saved = errno;
    if (a_fd >= 0) close (a_fd);
    if (b_fd >= 0) close (b_fd);
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                 "UDP loopback pair: %s", g_strerror (saved));
    return FALSE;
  }
}

void
g_tls_connection_apple_release_bounce_fd (GTlsConnectionApple *self,
                                          int                  apple_fd)
{
  close (apple_fd);
}

#ifdef GIO_APPLE_PUBLIC_API_ONLY

gboolean
g_tls_connection_apple_setup_public_endpoint (GTlsConnectionApple  *self,
                                              guint16              *out_port,
                                              GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gboolean result;

  result = priv->is_dtls
      ? setup_public_dtls_endpoint (self, out_port, error)
      : setup_public_tls_endpoint (self, out_port, error);
  if (result)
    priv->public_endpoint_pending = TRUE;

  return result;
}

static gboolean
setup_public_tls_endpoint (GTlsConnectionApple  *self,
                           guint16              *out_port,
                           GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  int listen_fd;
  guint16 port;

  if (!make_tcp_loopback_listener (&listen_fd, &port, error))
    return FALSE;

  priv->public_listen_fd = listen_fd;
  *out_port = port;
  return TRUE;
}

static gboolean
make_tcp_loopback_listener (int      *out_listen_fd,
                            guint16  *out_port,
                            GError  **error)
{
  int listen_fd = -1;
  struct sockaddr_in addr = { 0 };
  socklen_t addr_len = sizeof addr;

  listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0)
    goto syscall_fail;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (listen_fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    goto syscall_fail;
  if (getsockname (listen_fd, (struct sockaddr *) &addr, &addr_len) < 0)
    goto syscall_fail;
  if (listen (listen_fd, 1) < 0)
    goto syscall_fail;

  *out_listen_fd = listen_fd;
  *out_port = ntohs (addr.sin_port);
  return TRUE;

syscall_fail:
  {
    int saved = errno;
    if (listen_fd >= 0) close (listen_fd);
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                 "TCP loopback listener: %s", g_strerror (saved));
    return FALSE;
  }
}

static gboolean
setup_public_dtls_endpoint (GTlsConnectionApple  *self,
                            guint16              *out_port,
                            GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  int udp_fd;
  guint16 port;

  if (!make_udp_loopback_local (&udp_fd, &port, error))
    return FALSE;

  priv->bounce_fd = udp_fd;
  *out_port = port;
  return TRUE;
}

static gboolean
make_udp_loopback_local (int      *out_fd,
                         guint16  *out_port,
                         GError  **error)
{
  int fd = -1;
  struct sockaddr_in addr = { 0 };
  socklen_t addr_len = sizeof addr;

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    goto syscall_fail;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    goto syscall_fail;
  if (getsockname (fd, (struct sockaddr *) &addr, &addr_len) < 0)
    goto syscall_fail;

  *out_fd = fd;
  *out_port = ntohs (addr.sin_port);
  return TRUE;

syscall_fail:
  {
    int saved = errno;
    if (fd >= 0) close (fd);
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                 "UDP loopback local: %s", g_strerror (saved));
    return FALSE;
  }
}

nw_connection_t
g_tls_connection_apple_listen_public_endpoint (GTlsConnectionApple *self,
                                                nw_parameters_t      parameters,
                                                GError             **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  __block nw_listener_state_t listener_state = nw_listener_state_invalid;
  __block bool                ready_signaled = false;
  __block nw_connection_t     captured = NULL;
  dispatch_semaphore_t        ready_sem;
  dispatch_semaphore_t        new_conn_sem;
  nw_listener_t               listener;
  guint16                     listener_port;
  int                         local_fd = -1;

  ready_sem = dispatch_semaphore_create (0);
  new_conn_sem = dispatch_semaphore_create (0);

  listener = nw_listener_create_with_port ("0", parameters);
  if (listener == NULL)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("nw_listener_create_with_port returned NULL"));
      goto release_sems;
    }

  nw_listener_set_state_changed_handler (listener,
      ^(nw_listener_state_t state, nw_error_t err) {
        listener_state = state;
        if (!ready_signaled
            && (state == nw_listener_state_ready
                || state == nw_listener_state_failed
                || state == nw_listener_state_cancelled))
          {
            ready_signaled = true;
            dispatch_semaphore_signal (ready_sem);
          }
      });

  nw_listener_set_new_connection_handler (listener,
      ^(nw_connection_t connection) {
        if (captured == NULL)
          {
            nw_retain (connection);
            captured = connection;
            dispatch_semaphore_signal (new_conn_sem);
          }
        else
          nw_connection_cancel (connection);
      });

  nw_listener_set_queue (listener, priv->queue);
  nw_listener_start (listener);

  dispatch_semaphore_wait (ready_sem, DISPATCH_TIME_FOREVER);
  if (listener_state != nw_listener_state_ready)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("nw_listener never reached ready state"));
      goto release_listener;
    }

  listener_port = nw_listener_get_port (listener);

  if (priv->is_dtls
      ? !dial_loopback_udp (listener_port, &local_fd, error)
      : !dial_loopback_tcp (listener_port, &local_fd, error))
    goto release_listener;

  if (!adopt_bounce_fd (self, local_fd, !priv->is_dtls, error))
    goto release_listener;

  dispatch_semaphore_wait (new_conn_sem, DISPATCH_TIME_FOREVER);

  detach_listener_rendezvous (listener, priv->queue);

  priv->public_listener = listener;

  dispatch_release (ready_sem);
  dispatch_release (new_conn_sem);

  return captured;

release_listener:
  detach_listener_rendezvous (listener, priv->queue);
  nw_listener_cancel (listener);
  dispatch_sync (priv->queue, ^{ });
  nw_release (listener);

release_sems:
  dispatch_release (ready_sem);
  dispatch_release (new_conn_sem);

  return NULL;
}

static void
detach_listener_rendezvous (nw_listener_t    listener,
                            dispatch_queue_t queue)
{
  nw_listener_set_state_changed_handler (listener,
      ^(nw_listener_state_t state, nw_error_t err) {
      });
  nw_listener_set_new_connection_handler (listener,
      ^(nw_connection_t connection) {
        nw_connection_cancel (connection);
      });
  dispatch_sync (queue, ^{ });
}

static gboolean
dial_loopback_tcp (guint16  port,
                   int     *out_fd,
                   GError **error)
{
  int fd = -1;
  struct sockaddr_in addr = { 0 };
  int one = 1;

  fd = socket (AF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    goto syscall_fail;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons (port);
  if (connect (fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    goto syscall_fail;

  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

  *out_fd = fd;
  return TRUE;

syscall_fail:
  {
    int saved = errno;
    if (fd >= 0) close (fd);
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                 "TCP loopback dial: %s", g_strerror (saved));
    return FALSE;
  }
}

static gboolean
dial_loopback_udp (guint16  port,
                   int     *out_fd,
                   GError **error)
{
  int fd = -1;
  struct sockaddr_in addr = { 0 };

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd < 0)
    goto syscall_fail;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = htons (port);
  if (connect (fd, (struct sockaddr *) &addr, sizeof addr) < 0)
    goto syscall_fail;

  *out_fd = fd;
  return TRUE;

syscall_fail:
  {
    int saved = errno;
    if (fd >= 0) close (fd);
    g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                 "UDP loopback dial: %s", g_strerror (saved));
    return FALSE;
  }
}

static gboolean
start_public_bridge (GTlsConnectionApple  *self,
                     GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  int base_fd;

  if (!extract_base_fd (self, &base_fd, error))
    return FALSE;

  fcntl (base_fd, F_SETFL, fcntl (base_fd, F_GETFL, 0) | O_NONBLOCK);
  fcntl (priv->bounce_fd, F_SETFL, fcntl (priv->bounce_fd, F_GETFL, 0) | O_NONBLOCK);

  priv->bridge_pump_forward = bridge_pump_new (base_fd, priv->bounce_fd, priv->is_dtls, priv->queue);
  priv->bridge_pump_reverse = bridge_pump_new (priv->bounce_fd, base_fd, priv->is_dtls, priv->queue);

  bridge_pump_start (priv->bridge_pump_forward);
  bridge_pump_start (priv->bridge_pump_reverse);

  return TRUE;
}

static void
stop_public_bridge (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  BridgePump *forward = priv->bridge_pump_forward;
  BridgePump *reverse = priv->bridge_pump_reverse;
  void (^cancel_block) (void);

  if (forward == NULL && reverse == NULL)
    return;

  priv->bridge_pump_forward = NULL;
  priv->bridge_pump_reverse = NULL;

  cancel_block = ^{
    if (forward != NULL)
      bridge_pump_cancel (forward);
    if (reverse != NULL)
      bridge_pump_cancel (reverse);
  };

  if (running_on_dispatch_queue (priv->queue))
    cancel_block ();
  else
    dispatch_sync (priv->queue, cancel_block);
}

static gboolean
extract_base_fd (GTlsConnectionApple  *self,
                 int                  *out_fd,
                 GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  GSocket *sock = NULL;

  if (priv->is_dtls && G_IS_SOCKET (priv->base_socket))
    sock = G_SOCKET (priv->base_socket);
  else if (!priv->is_dtls && G_IS_SOCKET_CONNECTION (priv->base_iostream))
    sock = g_socket_connection_get_socket (G_SOCKET_CONNECTION (priv->base_iostream));

  if (sock == NULL)
    {
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("Apple TLS public mode requires a socket-backed base stream"));
      return FALSE;
    }

  *out_fd = g_socket_get_fd (sock);
  return TRUE;
}

static BridgePump *
bridge_pump_new (int               src_fd,
                 int               dst_fd,
                 gboolean          is_datagram,
                 dispatch_queue_t  queue)
{
  BridgePump *pump = g_new0 (BridgePump, 1);

  pump->src_fd = src_fd;
  pump->dst_fd = dst_fd;
  pump->is_datagram = is_datagram;
  pump->queue = queue;
  dispatch_retain (queue);
  pump->buffer_capacity = TRANSFER_BUFFER_SIZE;
  pump->buffer = g_malloc (pump->buffer_capacity);
  pump->read_suspended = TRUE;

  return pump;
}

static void
bridge_pump_start (BridgePump *pump)
{
  dispatch_source_t read_src;

  read_src = dispatch_source_create (DISPATCH_SOURCE_TYPE_READ,
                                      (uintptr_t) pump->src_fd, 0, pump->queue);
  pump->read_src = read_src;
  pump->outstanding_sources++;
  dispatch_source_set_event_handler (read_src, ^{
      bridge_pump_handle_readable (pump);
  });
  dispatch_source_set_cancel_handler (read_src, ^{
      bridge_pump_handle_source_cancelled (pump, read_src);
  });
  dispatch_resume (read_src);
  pump->read_suspended = FALSE;
}

static void
bridge_pump_cancel (BridgePump *pump)
{
  if (pump->stopping)
    return;

  bridge_pump_drain_pending (pump);

  pump->stopping = TRUE;
  pump->stopped = TRUE;

  if (pump->read_src != NULL)
    {
      if (pump->read_suspended)
        {
          dispatch_resume (pump->read_src);
          pump->read_suspended = FALSE;
        }
      dispatch_source_cancel (pump->read_src);
    }
  if (pump->write_src != NULL)
    dispatch_source_cancel (pump->write_src);
}

static void
bridge_pump_handle_readable (BridgePump *pump)
{
  ssize_t n;

  if (pump->stopped)
    return;

  do
    n = recv (pump->src_fd, pump->buffer, pump->buffer_capacity, 0);
  while (n < 0 && errno == EINTR);

  if (n == 0 && !pump->is_datagram)
    {
      pump->stopped = TRUE;
      dispatch_suspend (pump->read_src);
      pump->read_suspended = TRUE;
      shutdown (pump->dst_fd, SHUT_WR);
      return;
    }
  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      pump->stopped = TRUE;
      dispatch_suspend (pump->read_src);
      pump->read_suspended = TRUE;
      return;
    }

  pump->buffer_offset = 0;
  pump->buffer_length = (gsize) n;

  dispatch_suspend (pump->read_src);
  pump->read_suspended = TRUE;

  bridge_pump_drain (pump);
}

static void
bridge_pump_drain (BridgePump *pump)
{
  while (pump->buffer_offset < pump->buffer_length)
    {
      ssize_t n;

      do
        n = send (pump->dst_fd, pump->buffer + pump->buffer_offset,
                  pump->buffer_length - pump->buffer_offset, 0);
      while (n < 0 && errno == EINTR);

      if (n >= 0)
        {
          pump->buffer_offset += (gsize) n;
          continue;
        }
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
          if (pump->write_src == NULL)
            {
              dispatch_source_t write_src = dispatch_source_create (DISPATCH_SOURCE_TYPE_WRITE,
                                                                     (uintptr_t) pump->dst_fd, 0, pump->queue);
              pump->write_src = write_src;
              pump->outstanding_sources++;
              dispatch_source_set_event_handler (write_src, ^{
                  bridge_pump_handle_writable (pump);
              });
              dispatch_source_set_cancel_handler (write_src, ^{
                  bridge_pump_handle_source_cancelled (pump, write_src);
              });
              dispatch_resume (write_src);
            }
          return;
        }
      pump->stopped = TRUE;
      return;
    }

  pump->buffer_offset = 0;
  pump->buffer_length = 0;

  if (pump->write_src != NULL)
    {
      dispatch_source_cancel (pump->write_src);
      pump->write_src = NULL;
    }

  if (!pump->stopped && pump->read_suspended)
    {
      dispatch_resume (pump->read_src);
      pump->read_suspended = FALSE;
    }
}

static void
bridge_pump_handle_writable (BridgePump *pump)
{
  if (pump->stopped)
    return;
  bridge_pump_drain (pump);
}

static void
bridge_pump_handle_source_cancelled (BridgePump        *pump,
                                     dispatch_source_t  src)
{
  dispatch_release (src);
  pump->outstanding_sources--;
  if (pump->stopping && pump->outstanding_sources == 0)
    bridge_pump_free (pump);
}

static void
bridge_pump_drain_pending (BridgePump *pump)
{
  gint64 deadline;

  if (pump->stopped || pump->is_datagram)
    return;

  deadline = g_get_monotonic_time () + 250 * G_TIME_SPAN_MILLISECOND;

  while (TRUE)
    {
      ssize_t n;

      if (pump->buffer_offset == pump->buffer_length)
        {
          struct pollfd pfd = { pump->src_fd, POLLIN, 0 };
          gint64 remaining_us = deadline - g_get_monotonic_time ();
          int poll_timeout_ms = (remaining_us > 0) ? (int) (remaining_us / 1000) : 0;
          int pr;

          do
            pr = poll (&pfd, 1, poll_timeout_ms);
          while (pr < 0 && errno == EINTR);
          if (pr <= 0)
            return;

          do
            n = recv (pump->src_fd, pump->buffer, pump->buffer_capacity, MSG_DONTWAIT);
          while (n < 0 && errno == EINTR);

          if (n <= 0)
            {
              if (n == 0)
                shutdown (pump->dst_fd, SHUT_WR);
              return;
            }

          pump->buffer_offset = 0;
          pump->buffer_length = (gsize) n;
        }

      while (pump->buffer_offset < pump->buffer_length)
        {
          do
            n = send (pump->dst_fd, pump->buffer + pump->buffer_offset,
                      pump->buffer_length - pump->buffer_offset, MSG_DONTWAIT);
          while (n < 0 && errno == EINTR);

          if (n < 0)
            return;
          pump->buffer_offset += (gsize) n;
        }
    }
}

static void
bridge_pump_free (BridgePump *pump)
{
  dispatch_release (pump->queue);
  g_free (pump->buffer);
  g_free (pump);
}

#endif /* GIO_APPLE_PUBLIC_API_ONLY */

static gboolean
running_on_dispatch_queue (dispatch_queue_t queue)
{
  return dispatch_get_specific (queue_marker_key) == queue;
}

GWeakRef *
g_tls_connection_apple_get_weak_self (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  if (priv->weak_self == NULL)
    {
      priv->weak_self = g_new0 (GWeakRef, 1);
      g_weak_ref_init (priv->weak_self, self);
    }

  return priv->weak_self;
}

void
g_tls_connection_apple_install_verify_block (GTlsConnectionApple   *self,
                                              sec_protocol_options_t options)
{
  GWeakRef *weak_self = g_tls_connection_apple_get_weak_self (self);

  sec_protocol_options_set_verify_block (options,
      ^(sec_protocol_metadata_t metadata,
        sec_trust_t             trust,
        sec_protocol_verify_complete_t complete) {
        GTlsConnectionApple *strong_self = g_weak_ref_get (weak_self);
        GTlsConnectionApplePrivate *strong_priv;
        GTlsCertificateApple *chain;
        gboolean accepted;

        if (strong_self == NULL)
          {
            complete (FALSE);
            return;
          }

        strong_priv = PRIV (strong_self);
        chain = wrap_peer_chain (metadata);

        g_mutex_lock (&strong_priv->state_mutex);
        g_clear_object (&strong_priv->peer_cert);
        strong_priv->peer_cert = chain;

        g_clear_pointer (&strong_priv->verify_trust, nw_release);
        strong_priv->verify_trust = trust;
        nw_retain (strong_priv->verify_trust);
        strong_priv->verify_pending = TRUE;
        g_cond_broadcast (&strong_priv->state_cond);

        while (strong_priv->verify_pending &&
               strong_priv->state != STATE_FAILED &&
               strong_priv->state != STATE_CLOSED)
          g_cond_wait (&strong_priv->state_cond, &strong_priv->state_mutex);

        if (strong_priv->verify_pending)
          {
            strong_priv->verify_pending = FALSE;
            strong_priv->verify_accepted = FALSE;
            g_clear_pointer (&strong_priv->verify_trust, nw_release);
          }

        accepted = strong_priv->verify_accepted;
        g_mutex_unlock (&strong_priv->state_mutex);

        g_object_unref (strong_self);

        complete (accepted);
      },
      g_tls_connection_apple_get_queue (self));
}

static GTlsCertificateApple *
wrap_peer_chain (sec_protocol_metadata_t metadata)
{
  GTlsCertificate *leaf = NULL;
  CFMutableArrayRef refs = CFArrayCreateMutable (kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  CFIndex count, i;

  sec_protocol_metadata_access_peer_certificate_chain (metadata,
      ^(sec_certificate_t sec_cert) {
        SecCertificateRef cert_ref = sec_certificate_copy_ref (sec_cert);
        CFArrayAppendValue (refs, cert_ref);
        CFRelease (cert_ref);
      });

  count = CFArrayGetCount (refs);
  for (i = count - 1; i >= 0; i--)
    {
      SecCertificateRef ref = (SecCertificateRef) CFArrayGetValueAtIndex (refs, i);
      GTlsCertificate *next = g_tls_certificate_apple_new_from_sec (ref, NULL, leaf);
      g_clear_object (&leaf);
      leaf = next;
    }

  CFRelease (refs);
  return leaf != NULL ? G_TLS_CERTIFICATE_APPLE (leaf) : NULL;
}

void
g_tls_connection_apple_add_advertised_protocols (GTlsConnection        *tls,
                                                 sec_protocol_options_t options)
{
  gchar **protocols = NULL;
  guint i;

  g_object_get (tls, "advertised-protocols", &protocols, NULL);
  if (protocols == NULL)
    return;

  for (i = 0; protocols[i] != NULL; i++)
    sec_protocol_options_add_tls_application_protocol (options, protocols[i]);

  g_strfreev (protocols);
}

void
g_tls_connection_apple_attach (GTlsConnectionApple *self,
                               nw_connection_t      connection)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  GWeakRef *weak_self = g_tls_connection_apple_get_weak_self (self);
  nw_connection_t captured_connection;

  nw_retain (connection);
  priv->connection = connection;
  nw_connection_set_queue (connection, priv->queue);

  captured_connection = connection;
  nw_connection_set_state_changed_handler (connection,
      ^(nw_connection_state_t nw_state, nw_error_t nw_error) {
        GTlsConnectionApple *self = g_weak_ref_get (weak_self);

        if (self != NULL)
          {
            publish_nw_state (self, nw_state, nw_error);
            if (nw_state == nw_connection_state_failed)
              nw_connection_cancel (captured_connection);

            g_object_unref (self);
          }

        if (nw_state == nw_connection_state_cancelled)
          {
            g_weak_ref_clear (weak_self);
            g_free (weak_self);
          }
      });

  g_mutex_lock (&priv->state_mutex);
  priv->state = STATE_HANDSHAKING;
  g_mutex_unlock (&priv->state_mutex);

  nw_connection_start (connection);

#ifdef GIO_APPLE_PUBLIC_API_ONLY
  if (priv->public_endpoint_pending)
    {
      GError *finalize_error = NULL;

      if (!finalize_public_bridge (self, &finalize_error))
        {
          g_mutex_lock (&priv->state_mutex);
          fail_locked (priv, finalize_error);
          g_mutex_unlock (&priv->state_mutex);
          wake_up_wakeup_source (priv);
          return;
        }
    }

  if (priv->bounce_fd >= 0)
    {
      GError *bridge_error = NULL;

      if (!start_public_bridge (self, &bridge_error))
        {
          g_mutex_lock (&priv->state_mutex);
          fail_locked (priv, bridge_error);
          g_mutex_unlock (&priv->state_mutex);
          wake_up_wakeup_source (priv);
        }
    }
#else
  if (priv->bounce_socket != NULL)
    {
      if (priv->is_dtls)
        start_datagram_bridge (self);
      else
        start_stream_bridge (self);
    }
#endif
}

#ifdef GIO_APPLE_PUBLIC_API_ONLY

static gboolean
finalize_public_bridge (GTlsConnectionApple  *self,
                        GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  gboolean result;

  result = priv->is_dtls
      ? finalize_public_dtls_bridge (self, error)
      : finalize_public_tls_bridge (self, error);
  if (result)
    priv->public_endpoint_pending = FALSE;

  return result;
}

static gboolean
finalize_public_tls_bridge (GTlsConnectionApple  *self,
                            GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  int our_fd;
  int one = 1;

  our_fd = accept (priv->public_listen_fd, NULL, NULL);
  if (our_fd < 0)
    {
      int saved = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                   "accept on loopback listener: %s", g_strerror (saved));
      return FALSE;
    }

  close (priv->public_listen_fd);
  priv->public_listen_fd = -1;

  setsockopt (our_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

  return adopt_bounce_fd (self, our_fd, TRUE, error);
}

static gboolean
finalize_public_dtls_bridge (GTlsConnectionApple  *self,
                             GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  struct sockaddr_in peer;

  if (!wait_for_first_datagram (priv->bounce_fd, &peer, error))
    return FALSE;

  if (connect (priv->bounce_fd, (struct sockaddr *) &peer, sizeof peer) < 0)
    {
      int saved = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                   "connect bounce UDP fd to peer: %s", g_strerror (saved));
      return FALSE;
    }

  return adopt_bounce_fd (self, priv->bounce_fd, FALSE, error);
}

static gboolean
wait_for_first_datagram (int                  fd,
                         struct sockaddr_in  *out_peer,
                         GError             **error)
{
  guint8 probe;
  socklen_t addr_len = sizeof *out_peer;
  ssize_t n;

  do
    n = recvfrom (fd, &probe, sizeof probe, MSG_PEEK,
                  (struct sockaddr *) out_peer, &addr_len);
  while (n < 0 && errno == EINTR);

  if (n < 0)
    {
      int saved = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (saved),
                   "peek for first datagram on loopback: %s", g_strerror (saved));
      return FALSE;
    }

  return TRUE;
}

static gboolean
adopt_bounce_fd (GTlsConnectionApple  *self,
                 int                   fd,
                 gboolean              wrap_as_iostream,
                 GError              **error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  GSocket *bounce_socket;
  GSocketConnection *bounce_connection;

  bounce_socket = g_socket_new_from_fd (fd, error);
  if (bounce_socket == NULL)
    {
      close (fd);
      return FALSE;
    }
  g_socket_set_blocking (bounce_socket, FALSE);

  priv->bounce_fd = fd;
  priv->bounce_socket = bounce_socket;

  if (wrap_as_iostream)
    {
      bounce_connection = g_socket_connection_factory_create_connection (bounce_socket);
      priv->bounce_istream = g_object_ref (g_io_stream_get_input_stream (G_IO_STREAM (bounce_connection)));
      priv->bounce_ostream = g_object_ref (g_io_stream_get_output_stream (G_IO_STREAM (bounce_connection)));
      g_object_unref (bounce_connection);
    }

  return TRUE;
}

#endif /* GIO_APPLE_PUBLIC_API_ONLY */

static void
publish_nw_state (GTlsConnectionApple   *self,
                  nw_connection_state_t  nw_state,
                  nw_error_t             nw_error)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  g_mutex_lock (&priv->state_mutex);

  switch (nw_state)
    {
    case nw_connection_state_ready:
      priv->state = STATE_READY;
      capture_negotiated_metadata_locked (self);
      kick_receive_locked (self);
      break;
    case nw_connection_state_failed:
      fail_locked (priv, error_from_nw_error (nw_error, _("TLS handshake failed")));
      break;
    case nw_connection_state_cancelled:
      priv->state = STATE_CLOSED;
      break;
    case nw_connection_state_invalid:
    case nw_connection_state_waiting:
    case nw_connection_state_preparing:
    default:
      break;
    }

  g_cond_broadcast (&priv->state_cond);
  g_mutex_unlock (&priv->state_mutex);
  wake_up_wakeup_source (priv);
  wake_up_base_sources (priv);
}

static void
capture_negotiated_metadata_locked (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);
  nw_protocol_definition_t tls_definition;
  nw_protocol_metadata_t protocol_metadata;
  sec_protocol_metadata_t sec_metadata;
  char *alpn_copy = NULL;
  const char *alpn;

  tls_definition = nw_protocol_copy_tls_definition ();
  protocol_metadata = nw_connection_copy_protocol_metadata (priv->connection, tls_definition);
  nw_release (tls_definition);

  if (!protocol_metadata)
    return;

  sec_metadata = (sec_protocol_metadata_t) protocol_metadata;

  if (__builtin_available (macOS 15.5, iOS 18.5, tvOS 18.5, watchOS 11.5, *))
    {
      alpn_copy = (char *) sec_protocol_metadata_copy_negotiated_protocol (sec_metadata);
      alpn = alpn_copy;
    }
  else
    {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
      alpn = sec_protocol_metadata_get_negotiated_protocol (sec_metadata);
#pragma clang diagnostic pop
    }
  g_free (priv->negotiated_alpn);
  priv->negotiated_alpn = alpn ? g_strdup (alpn) : NULL;
  free (alpn_copy);

  priv->protocol_version = translate_protocol_version (
      sec_protocol_metadata_get_negotiated_tls_protocol_version (sec_metadata));

  g_free (priv->ciphersuite_name);
  priv->ciphersuite_name = format_ciphersuite (
      sec_protocol_metadata_get_negotiated_tls_ciphersuite (sec_metadata));

  g_clear_object (&priv->peer_cert);
  priv->peer_cert = wrap_peer_chain (sec_metadata);

  nw_release (protocol_metadata);
}

static GTlsProtocolVersion
translate_protocol_version (tls_protocol_version_t version)
{
  switch (version)
    {
    case tls_protocol_version_TLSv12:  return G_TLS_PROTOCOL_VERSION_TLS_1_2;
    case tls_protocol_version_TLSv13:  return G_TLS_PROTOCOL_VERSION_TLS_1_3;
    case tls_protocol_version_DTLSv12: return G_TLS_PROTOCOL_VERSION_DTLS_1_2;
    default: return G_TLS_PROTOCOL_VERSION_UNKNOWN;
    }
}

static gchar *
format_ciphersuite (tls_ciphersuite_t suite)
{
  switch (suite)
    {
    case tls_ciphersuite_AES_128_GCM_SHA256:       return g_strdup ("TLS_AES_128_GCM_SHA256");
    case tls_ciphersuite_AES_256_GCM_SHA384:       return g_strdup ("TLS_AES_256_GCM_SHA384");
    case tls_ciphersuite_CHACHA20_POLY1305_SHA256: return g_strdup ("TLS_CHACHA20_POLY1305_SHA256");
    default: return g_strdup_printf ("TLS_CIPHER_%04X", (unsigned) suite);
    }
}

#ifndef GIO_APPLE_PUBLIC_API_ONLY

static void
start_stream_bridge (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  priv->forward_stream_pump = stream_pump_new (priv->bridge_context, priv->io_cancellable,
      priv->base_istream, priv->bounce_ostream,
      priv->base_input_pollable, TRUE,
      TRANSFER_BUFFER_SIZE);
  priv->reverse_stream_pump = stream_pump_new (priv->bridge_context, priv->io_cancellable,
      priv->bounce_istream, priv->base_ostream,
      TRUE, priv->base_output_pollable,
      TRANSFER_BUFFER_SIZE);

  stream_pump_schedule (priv->forward_stream_pump);
  stream_pump_schedule (priv->reverse_stream_pump);
}

static void
stop_stream_bridge (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  if (priv->forward_stream_pump)
    {
      stream_pump_stop (priv->forward_stream_pump);
      stream_pump_unref (priv->forward_stream_pump);
      priv->forward_stream_pump = NULL;
    }
  if (priv->reverse_stream_pump)
    {
      stream_pump_stop (priv->reverse_stream_pump);
      stream_pump_unref (priv->reverse_stream_pump);
      priv->reverse_stream_pump = NULL;
    }
}

static StreamPump *
stream_pump_new (GMainContext   *context,
                 GCancellable   *cancellable,
                 GInputStream   *source,
                 GOutputStream  *sink,
                 gboolean        source_pollable,
                 gboolean        sink_pollable,
                 gsize           buffer_capacity)
{
  StreamPump *pump = g_new0 (StreamPump, 1);

  pump->ref_count = 1;
  pump->context = g_main_context_ref (context);
  pump->cancellable = g_object_ref (cancellable);
  pump->source = g_object_ref (source);
  pump->sink = g_object_ref (sink);
  pump->source_pollable = source_pollable;
  pump->sink_pollable = sink_pollable;
  pump->buffer = g_malloc (buffer_capacity);
  pump->buffer_capacity = buffer_capacity;
  return pump;
}

static StreamPump *
stream_pump_ref (StreamPump *pump)
{
  g_atomic_int_inc (&pump->ref_count);
  return pump;
}

static void
stream_pump_unref (StreamPump *pump)
{
  if (!g_atomic_int_dec_and_test (&pump->ref_count))
    return;

  g_object_unref (pump->source);
  g_object_unref (pump->sink);
  g_object_unref (pump->cancellable);
  g_main_context_unref (pump->context);
  g_free (pump->buffer);
  g_free (pump);
}

static void
stream_pump_stop (StreamPump *pump)
{
  pump->stopped = TRUE;
  if (pump->source_ready_source)
    {
      g_source_destroy (pump->source_ready_source);
      g_source_unref (pump->source_ready_source);
      pump->source_ready_source = NULL;
    }
  if (pump->sink_ready_source)
    {
      g_source_destroy (pump->sink_ready_source);
      g_source_unref (pump->sink_ready_source);
      pump->sink_ready_source = NULL;
    }
}

static void
stream_pump_schedule (StreamPump *pump)
{
  g_main_context_invoke_full (pump->context, G_PRIORITY_DEFAULT,
                              stream_pump_drive,
                              stream_pump_ref (pump),
                              (GDestroyNotify) stream_pump_unref);
}

static gboolean
stream_pump_drive (gpointer user_data)
{
  StreamPump *pump = user_data;

  if (pump->stopped || g_cancellable_is_cancelled (pump->cancellable))
    return G_SOURCE_REMOVE;

  while (!pump->stopped)
    {
      if (pump->buffer_length == 0)
        {
          GError *error = NULL;

          if (pump->async_read_in_flight)
            return G_SOURCE_REMOVE;

          if (pump->source_pollable)
            {
              gssize n = g_pollable_input_stream_read_nonblocking (
                  G_POLLABLE_INPUT_STREAM (pump->source),
                  pump->buffer, pump->buffer_capacity,
                  pump->cancellable, &error);

              if (n < 0 && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
                {
                  g_clear_error (&error);
                  if (!pump->source_ready_source)
                    {
                      pump->source_ready_source = g_pollable_input_stream_create_source (
                          G_POLLABLE_INPUT_STREAM (pump->source), pump->cancellable);
                      g_source_set_callback (pump->source_ready_source,
                          (GSourceFunc) stream_pump_on_source_ready,
                          stream_pump_ref (pump),
                          (GDestroyNotify) stream_pump_unref);
                      g_source_attach (pump->source_ready_source, pump->context);
                    }
                  return G_SOURCE_REMOVE;
                }

              if (n <= 0)
                {
                  g_clear_error (&error);
                  pump->stopped = TRUE;
                  return G_SOURCE_REMOVE;
                }

              pump->buffer_length = n;
              pump->buffer_offset = 0;
            }
          else
            {
              pump->async_read_in_flight = TRUE;
              g_input_stream_read_async (pump->source,
                  pump->buffer, pump->buffer_capacity,
                  G_PRIORITY_DEFAULT, pump->cancellable,
                  stream_pump_on_read_done, stream_pump_ref (pump));
              return G_SOURCE_REMOVE;
            }
        }

      if (pump->async_write_in_flight)
        return G_SOURCE_REMOVE;

      if (pump->sink_pollable)
        {
          GError *error = NULL;
          gssize n = g_pollable_output_stream_write_nonblocking (
              G_POLLABLE_OUTPUT_STREAM (pump->sink),
              pump->buffer + pump->buffer_offset,
              pump->buffer_length - pump->buffer_offset,
              pump->cancellable, &error);

          if (n < 0 && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
            {
              g_clear_error (&error);
              if (!pump->sink_ready_source)
                {
                  pump->sink_ready_source = g_pollable_output_stream_create_source (
                      G_POLLABLE_OUTPUT_STREAM (pump->sink), pump->cancellable);
                  g_source_set_callback (pump->sink_ready_source,
                      (GSourceFunc) stream_pump_on_sink_ready,
                      stream_pump_ref (pump),
                      (GDestroyNotify) stream_pump_unref);
                  g_source_attach (pump->sink_ready_source, pump->context);
                }
              return G_SOURCE_REMOVE;
            }

          if (n <= 0)
            {
              g_clear_error (&error);
              pump->stopped = TRUE;
              return G_SOURCE_REMOVE;
            }

          pump->buffer_offset += n;
          if (pump->buffer_offset == pump->buffer_length)
            pump->buffer_length = 0;
        }
      else
        {
          pump->async_write_in_flight = TRUE;
          g_output_stream_write_async (pump->sink,
              pump->buffer + pump->buffer_offset,
              pump->buffer_length - pump->buffer_offset,
              G_PRIORITY_DEFAULT, pump->cancellable,
              stream_pump_on_write_done, stream_pump_ref (pump));
          return G_SOURCE_REMOVE;
        }
    }

  return G_SOURCE_REMOVE;
}

static gboolean
stream_pump_on_source_ready (GObject *stream,
                             gpointer user_data)
{
  StreamPump *pump = user_data;

  if (pump->source_ready_source)
    {
      g_source_unref (pump->source_ready_source);
      pump->source_ready_source = NULL;
    }

  if (!pump->stopped)
    stream_pump_drive (pump);
  return G_SOURCE_REMOVE;
}

static gboolean
stream_pump_on_sink_ready (GObject *stream,
                           gpointer user_data)
{
  StreamPump *pump = user_data;

  if (pump->sink_ready_source)
    {
      g_source_unref (pump->sink_ready_source);
      pump->sink_ready_source = NULL;
    }

  if (!pump->stopped)
    stream_pump_drive (pump);
  return G_SOURCE_REMOVE;
}

static void
stream_pump_on_read_done (GObject      *source,
                          GAsyncResult *result,
                          gpointer      user_data)
{
  StreamPump *pump = user_data;
  GError *error = NULL;
  gssize n;

  n = g_input_stream_read_finish (G_INPUT_STREAM (source), result, &error);
  pump->async_read_in_flight = FALSE;

  if (pump->stopped)
    {
      g_clear_error (&error);
      stream_pump_unref (pump);
      return;
    }

  if (n <= 0)
    {
      g_clear_error (&error);
      pump->stopped = TRUE;
      stream_pump_unref (pump);
      return;
    }

  pump->buffer_length = n;
  pump->buffer_offset = 0;
  stream_pump_drive (pump);
  stream_pump_unref (pump);
}

static void
stream_pump_on_write_done (GObject      *source,
                           GAsyncResult *result,
                           gpointer      user_data)
{
  StreamPump *pump = user_data;
  GError *error = NULL;
  gssize n;

  n = g_output_stream_write_finish (G_OUTPUT_STREAM (source), result, &error);
  pump->async_write_in_flight = FALSE;

  if (pump->stopped)
    {
      g_clear_error (&error);
      stream_pump_unref (pump);
      return;
    }

  if (n <= 0)
    {
      g_clear_error (&error);
      pump->stopped = TRUE;
      stream_pump_unref (pump);
      return;
    }

  pump->buffer_offset += n;
  if (pump->buffer_offset == pump->buffer_length)
    pump->buffer_length = 0;
  stream_pump_drive (pump);
  stream_pump_unref (pump);
}

static void
start_datagram_bridge (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  priv->forward_datagram_pump = datagram_pump_new (priv->bridge_context, priv->io_cancellable,
      priv->base_socket, G_DATAGRAM_BASED (priv->bounce_socket),
      TRANSFER_BUFFER_SIZE);
  priv->reverse_datagram_pump = datagram_pump_new (priv->bridge_context, priv->io_cancellable,
      G_DATAGRAM_BASED (priv->bounce_socket), priv->base_socket,
      TRANSFER_BUFFER_SIZE);

  datagram_pump_schedule (priv->forward_datagram_pump);
  datagram_pump_schedule (priv->reverse_datagram_pump);
}

static void
stop_datagram_bridge (GTlsConnectionApple *self)
{
  GTlsConnectionApplePrivate *priv = PRIV (self);

  if (priv->forward_datagram_pump)
    {
      datagram_pump_stop (priv->forward_datagram_pump);
      datagram_pump_unref (priv->forward_datagram_pump);
      priv->forward_datagram_pump = NULL;
    }
  if (priv->reverse_datagram_pump)
    {
      datagram_pump_stop (priv->reverse_datagram_pump);
      datagram_pump_unref (priv->reverse_datagram_pump);
      priv->reverse_datagram_pump = NULL;
    }
}

static DatagramPump *
datagram_pump_new (GMainContext   *context,
                   GCancellable   *cancellable,
                   GDatagramBased *source,
                   GDatagramBased *sink,
                   gsize           buffer_capacity)
{
  DatagramPump *pump = g_new0 (DatagramPump, 1);

  pump->ref_count = 1;
  pump->context = g_main_context_ref (context);
  pump->cancellable = g_object_ref (cancellable);
  pump->source = g_object_ref (source);
  pump->sink = g_object_ref (sink);
  pump->buffer = g_malloc (buffer_capacity);
  pump->buffer_capacity = buffer_capacity;
  return pump;
}

static DatagramPump *
datagram_pump_ref (DatagramPump *pump)
{
  g_atomic_int_inc (&pump->ref_count);
  return pump;
}

static void
datagram_pump_unref (DatagramPump *pump)
{
  if (!g_atomic_int_dec_and_test (&pump->ref_count))
    return;

  g_object_unref (pump->source);
  g_object_unref (pump->sink);
  g_object_unref (pump->cancellable);
  g_main_context_unref (pump->context);
  g_free (pump->buffer);
  g_free (pump);
}

static void
datagram_pump_stop (DatagramPump *pump)
{
  pump->stopped = TRUE;
  if (pump->source_ready_source)
    {
      g_source_destroy (pump->source_ready_source);
      g_source_unref (pump->source_ready_source);
      pump->source_ready_source = NULL;
    }
  if (pump->sink_ready_source)
    {
      g_source_destroy (pump->sink_ready_source);
      g_source_unref (pump->sink_ready_source);
      pump->sink_ready_source = NULL;
    }
}

static void
datagram_pump_schedule (DatagramPump *pump)
{
  g_main_context_invoke_full (pump->context, G_PRIORITY_DEFAULT,
                              datagram_pump_drive,
                              datagram_pump_ref (pump),
                              (GDestroyNotify) datagram_pump_unref);
}

static gboolean
datagram_pump_drive (gpointer user_data)
{
  DatagramPump *pump = user_data;

  while (!pump->stopped && !g_cancellable_is_cancelled (pump->cancellable))
    {
      GOutputVector out_vec;
      GOutputMessage out_msg = { NULL, &out_vec, 1, 0, NULL, 0 };
      GError *error = NULL;
      gint n;

      if (pump->pending_size == 0)
        {
          GInputVector in_vec = { pump->buffer, pump->buffer_capacity };
          GInputMessage in_msg = { NULL, &in_vec, 1, 0, 0, NULL, NULL };

          n = g_datagram_based_receive_messages (pump->source, &in_msg, 1,
                                                 G_SOCKET_MSG_NONE, 0,
                                                 pump->cancellable, &error);

          if (n < 0 && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
            {
              g_clear_error (&error);
              if (!pump->source_ready_source)
                {
                  pump->source_ready_source = g_datagram_based_create_source (
                      pump->source, G_IO_IN, pump->cancellable);
                  g_source_set_callback (pump->source_ready_source,
                      (GSourceFunc) datagram_pump_on_source_ready,
                      datagram_pump_ref (pump),
                      (GDestroyNotify) datagram_pump_unref);
                  g_source_attach (pump->source_ready_source, pump->context);
                }
              return G_SOURCE_REMOVE;
            }

          if (n <= 0)
            {
              g_clear_error (&error);
              pump->stopped = TRUE;
              return G_SOURCE_REMOVE;
            }

          pump->pending_size = in_msg.bytes_received;
        }

      out_vec.buffer = pump->buffer;
      out_vec.size = pump->pending_size;

      n = g_datagram_based_send_messages (pump->sink, &out_msg, 1,
                                          G_SOCKET_MSG_NONE, 0,
                                          pump->cancellable, &error);

      if (n < 0 && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK))
        {
          g_clear_error (&error);
          if (!pump->sink_ready_source)
            {
              pump->sink_ready_source = g_datagram_based_create_source (
                  pump->sink, G_IO_OUT, pump->cancellable);
              g_source_set_callback (pump->sink_ready_source,
                  (GSourceFunc) datagram_pump_on_sink_ready,
                  datagram_pump_ref (pump),
                  (GDestroyNotify) datagram_pump_unref);
              g_source_attach (pump->sink_ready_source, pump->context);
            }
          return G_SOURCE_REMOVE;
        }

      if (n <= 0)
        {
          g_clear_error (&error);
          pump->stopped = TRUE;
          return G_SOURCE_REMOVE;
        }

      pump->pending_size = 0;
    }

  return G_SOURCE_REMOVE;
}

static gboolean
datagram_pump_on_source_ready (GDatagramBased *datagram_based,
                               GIOCondition    condition,
                               gpointer        user_data)
{
  DatagramPump *pump = user_data;

  if (pump->source_ready_source)
    {
      g_source_unref (pump->source_ready_source);
      pump->source_ready_source = NULL;
    }

  if (!pump->stopped)
    datagram_pump_drive (pump);
  return G_SOURCE_REMOVE;
}

static gboolean
datagram_pump_on_sink_ready (GDatagramBased *datagram_based,
                             GIOCondition    condition,
                             gpointer        user_data)
{
  DatagramPump *pump = user_data;

  if (pump->sink_ready_source)
    {
      g_source_unref (pump->sink_ready_source);
      pump->sink_ready_source = NULL;
    }

  if (!pump->stopped)
    datagram_pump_drive (pump);
  return G_SOURCE_REMOVE;
}

#endif /* !GIO_APPLE_PUBLIC_API_ONLY */

nw_connection_t
g_tls_connection_apple_get_nw_connection (GTlsConnectionApple *self)
{
  g_return_val_if_fail (G_IS_TLS_CONNECTION_APPLE (self), NULL);
  return PRIV (self)->connection;
}

dispatch_queue_t
g_tls_connection_apple_get_queue (GTlsConnectionApple *self)
{
  g_return_val_if_fail (G_IS_TLS_CONNECTION_APPLE (self), NULL);
  return PRIV (self)->queue;
}

static GError *
error_from_nw_error (nw_error_t   nw_error,
                     const gchar *default_message)
{
  GTlsError tls_error = G_TLS_ERROR_MISC;
  int code;
  nw_error_domain_t domain;

  if (!nw_error)
    return g_error_new_literal (G_TLS_ERROR, G_TLS_ERROR_MISC, default_message);

  code = nw_error_get_error_code (nw_error);
  domain = nw_error_get_error_domain (nw_error);

  if (domain == nw_error_domain_tls)
    {
      switch (code)
        {
        case errSSLBadCert:
        case errSSLPeerBadCert:
        case errSSLNoRootCert:
        case errSSLUnknownRootCert:
        case errSSLCertExpired:
        case errSSLCertNotYetValid:
        case errSSLHostNameMismatch:
        case errSSLXCertChainInvalid:
        case errSSLPeerCertExpired:
        case errSSLPeerCertRevoked:
        case errSSLPeerUnknownCA:
          tls_error = G_TLS_ERROR_BAD_CERTIFICATE;
          break;
        case errSSLPeerCertUnknown:
          tls_error = G_TLS_ERROR_CERTIFICATE_REQUIRED;
          break;
        case errSSLPeerHandshakeFail:
        case errSSLPeerProtocolVersion:
        case errSSLNegotiation:
        case errSSLFatalAlert:
          tls_error = G_TLS_ERROR_HANDSHAKE;
          break;
        case errSSLClosedNoNotify:
        case errSSLClosedAbort:
          tls_error = G_TLS_ERROR_EOF;
          break;
        case errSSLCertificateRequired:
          tls_error = G_TLS_ERROR_CERTIFICATE_REQUIRED;
          break;
        case errSSLInappropriateFallback:
          tls_error = G_TLS_ERROR_INAPPROPRIATE_FALLBACK;
          break;
        }
    }

  return g_error_new (G_TLS_ERROR, tls_error,
                      "%s (nw_error domain=%d code=%d)",
                      default_message, (int) domain, code);
}

static void
fail_locked (GTlsConnectionApplePrivate *priv,
             GError                     *take_error)
{
  priv->state = STATE_FAILED;
  g_clear_error (&priv->fatal_error);
  priv->fatal_error = take_error;
}

static void
wake_up_wakeup_source (GTlsConnectionApplePrivate *priv)
{
  g_source_set_ready_time (priv->wakeup_source, 0);
}

static void
wake_up_base_sources (GTlsConnectionApplePrivate *priv)
{
  GList *l;

  g_mutex_lock (&priv->base_sources_mutex);
  for (l = priv->base_sources; l != NULL; l = l->next)
    {
      AppleBaseSource *s = l->data;
      if (s->attached_context != NULL)
        g_main_context_wakeup (s->attached_context);
    }
  g_mutex_unlock (&priv->base_sources_mutex);
}

static gint64
deadline_from_timeout (gint64 timeout_us)
{
  if (timeout_us < 0)
    return -1;
  return g_get_monotonic_time () + timeout_us;
}

static gboolean
wait_for_progress_locked (GTlsConnectionApplePrivate *priv,
                          gint64                      deadline,
                          GCancellable               *cancellable)
{
  if (g_cancellable_is_cancelled (cancellable))
    return FALSE;
  if (deadline < 0)
    {
      g_cond_wait (&priv->state_cond, &priv->state_mutex);
      return TRUE;
    }
  return g_cond_wait_until (&priv->state_cond, &priv->state_mutex, deadline);
}

static GSource *
wakeup_source_new (void)
{
  static GSourceFuncs funcs = {
    NULL,
    NULL,
    on_wakeup_source_dispatch,
    NULL,
    NULL,
    NULL,
  };

  GSource *source = g_source_new (&funcs, sizeof (GSource));
  g_source_set_static_name (source, "gio-apple-tls wakeup");
  return source;
}

static gboolean
on_wakeup_source_dispatch (GSource     *source,
                           GSourceFunc  callback,
                           gpointer     user_data)
{
  g_source_set_ready_time (source, -1);
  if (callback)
    return callback (user_data);
  return G_SOURCE_CONTINUE;
}
