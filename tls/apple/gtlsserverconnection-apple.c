/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsserverconnection-apple.c
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

#include "gtlsserverconnection-apple.h"
#include "gtlscertificate-apple.h"
#include <glib/gi18n-lib.h>

extern nw_connection_t nw_connection_create_with_connected_socket_and_parameters (int fd, nw_parameters_t parameters);
extern void            nw_parameters_set_allow_joining_connected_fd (nw_parameters_t parameters, bool allow);
extern void            nw_parameters_set_server_mode (nw_parameters_t parameters, bool server_mode);

struct _GTlsServerConnectionApple
{
  GTlsConnectionApple parent_instance;

  GTlsAuthenticationMode authentication_mode;
};

enum {
  PROP_0,
  PROP_AUTHENTICATION_MODE,
};

static void     g_tls_server_connection_apple_get_property         (GObject    *object,
                                                                    guint       prop_id,
                                                                    GValue     *value,
                                                                    GParamSpec *pspec);
static void     g_tls_server_connection_apple_set_property         (GObject      *object,
                                                                    guint         prop_id,
                                                                    const GValue *value,
                                                                    GParamSpec   *pspec);
static gboolean g_tls_server_connection_apple_start_handshake      (GTlsConnectionApple *base_self,
                                                                    GError             **error);
static gboolean g_tls_server_connection_apple_initable_init        (GInitable     *initable,
                                                                    GCancellable  *cancellable,
                                                                    GError       **error);
static void     g_tls_server_connection_apple_server_interface_init (GTlsServerConnectionInterface *iface);
static void     g_tls_server_connection_apple_dtls_iface_init      (GDtlsServerConnectionInterface *iface);
static void     g_tls_server_connection_apple_initable_iface_init  (GInitableIface                *iface);

static void     apply_server_tls_options                            (GTlsServerConnectionApple *self,
                                                                     sec_protocol_options_t     options);

G_DEFINE_TYPE_WITH_CODE (GTlsServerConnectionApple, g_tls_server_connection_apple,
                         G_TYPE_TLS_CONNECTION_APPLE,
                         G_IMPLEMENT_INTERFACE (G_TYPE_TLS_SERVER_CONNECTION,
                                                g_tls_server_connection_apple_server_interface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_DTLS_SERVER_CONNECTION,
                                                g_tls_server_connection_apple_dtls_iface_init)
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE,
                                                g_tls_server_connection_apple_initable_iface_init))

static void
g_tls_server_connection_apple_class_init (GTlsServerConnectionAppleClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  GTlsConnectionAppleClass *apple_class = (GTlsConnectionAppleClass *) klass;

  object_class->get_property = g_tls_server_connection_apple_get_property;
  object_class->set_property = g_tls_server_connection_apple_set_property;

  apple_class->start_handshake = g_tls_server_connection_apple_start_handshake;

  g_object_class_override_property (object_class, PROP_AUTHENTICATION_MODE, "authentication-mode");
}

static void
g_tls_server_connection_apple_init (GTlsServerConnectionApple *self)
{
}

static void
g_tls_server_connection_apple_get_property (GObject    *object,
                                            guint       prop_id,
                                            GValue     *value,
                                            GParamSpec *pspec)
{
  GTlsServerConnectionApple *self = G_TLS_SERVER_CONNECTION_APPLE (object);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      g_value_set_enum (value, self->authentication_mode);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static void
g_tls_server_connection_apple_set_property (GObject      *object,
                                            guint         prop_id,
                                            const GValue *value,
                                            GParamSpec   *pspec)
{
  GTlsServerConnectionApple *self = G_TLS_SERVER_CONNECTION_APPLE (object);

  switch (prop_id)
    {
    case PROP_AUTHENTICATION_MODE:
      self->authentication_mode = g_value_get_enum (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
    }
}

static gboolean
g_tls_server_connection_apple_start_handshake (GTlsConnectionApple  *base_self,
                                               GError              **error)
{
  GTlsServerConnectionApple *self = G_TLS_SERVER_CONNECTION_APPLE (base_self);
  gboolean is_dtls = g_tls_connection_base_is_dtls (G_TLS_CONNECTION_BASE (self));
  nw_parameters_configure_protocol_block_t configure_sec =
      ^(nw_protocol_options_t proto_options) {
        sec_protocol_options_t sec_opts = nw_tls_copy_sec_protocol_options (proto_options);
        apply_server_tls_options (self, sec_opts);
        nw_release (sec_opts);
      };
  nw_parameters_t parameters = is_dtls
      ? nw_parameters_create_secure_udp (configure_sec, NW_PARAMETERS_DEFAULT_CONFIGURATION)
      : nw_parameters_create_secure_tcp (configure_sec, NW_PARAMETERS_DEFAULT_CONFIGURATION);
  int apple_fd;
  nw_connection_t connection;

  nw_parameters_set_allow_joining_connected_fd (parameters, true);
  nw_parameters_set_server_mode (parameters, true);

  apple_fd = g_tls_connection_apple_setup_bounce_transport (base_self, error);
  if (apple_fd < 0)
    {
      nw_release (parameters);
      return FALSE;
    }

  connection = nw_connection_create_with_connected_socket_and_parameters (apple_fd, parameters);
  nw_release (parameters);

  if (!connection)
    {
      g_tls_connection_apple_release_bounce_fd (base_self, apple_fd);
      g_set_error_literal (error, G_TLS_ERROR, G_TLS_ERROR_MISC,
                           _("nw_connection_create_with_connected_socket_and_parameters returned NULL"));
      return FALSE;
    }

  g_tls_connection_apple_attach (base_self, connection);
  nw_release (connection);

  return TRUE;
}

static void
apply_server_tls_options (GTlsServerConnectionApple *self,
                          sec_protocol_options_t     options)
{
  tls_protocol_version_t min_version;
  GTlsCertificate *local_cert;

  min_version = g_tls_connection_base_is_dtls (G_TLS_CONNECTION_BASE (self))
      ? tls_protocol_version_DTLSv12
      : tls_protocol_version_TLSv12;
  sec_protocol_options_set_min_tls_protocol_version (options, min_version);

  g_tls_connection_apple_add_advertised_protocols (G_TLS_CONNECTION (self), options);

  local_cert = g_tls_connection_get_certificate (G_TLS_CONNECTION (self));
  if (G_IS_TLS_CERTIFICATE_APPLE (local_cert))
    {
      SecIdentityRef identity = g_tls_certificate_apple_copy_identity (G_TLS_CERTIFICATE_APPLE (local_cert));
      if (identity)
        {
          CFMutableArrayRef intermediates = CFArrayCreateMutable (kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
          GTlsCertificate *issuer;
          sec_identity_t sec_identity;

          for (issuer = g_tls_certificate_get_issuer (local_cert);
               G_IS_TLS_CERTIFICATE_APPLE (issuer);
               issuer = g_tls_certificate_get_issuer (issuer))
            {
              SecCertificateRef issuer_cert = g_tls_certificate_apple_get_cert (G_TLS_CERTIFICATE_APPLE (issuer));
              if (issuer_cert)
                CFArrayAppendValue (intermediates, issuer_cert);
            }

          sec_identity = (CFArrayGetCount (intermediates) > 0)
              ? sec_identity_create_with_certificates (identity, intermediates)
              : sec_identity_create (identity);
          if (sec_identity)
            {
              sec_protocol_options_set_local_identity (options, sec_identity);
              nw_release (sec_identity);
            }

          CFRelease (intermediates);
          CFRelease (identity);
        }
    }

  if (self->authentication_mode == G_TLS_AUTHENTICATION_REQUIRED)
    {
      sec_protocol_options_set_peer_authentication_required (options, true);
      g_tls_connection_apple_install_verify_block (G_TLS_CONNECTION_APPLE (self), options);
    }
}

static void
g_tls_server_connection_apple_server_interface_init (GTlsServerConnectionInterface *iface)
{
}

static void
g_tls_server_connection_apple_dtls_iface_init (GDtlsServerConnectionInterface *iface)
{
}

static void
g_tls_server_connection_apple_initable_iface_init (GInitableIface *iface)
{
  iface->init = g_tls_server_connection_apple_initable_init;
}

static gboolean
g_tls_server_connection_apple_initable_init (GInitable     *initable,
                                             GCancellable  *cancellable,
                                             GError       **error)
{
  GTlsConnectionBase *tls_base = G_TLS_CONNECTION_BASE (initable);
  GTlsConnectionApple *base_self = G_TLS_CONNECTION_APPLE (initable);

  if (g_tls_connection_base_is_dtls (tls_base))
    return g_tls_connection_apple_bind_base_socket (base_self,
        g_tls_connection_base_get_base_socket (tls_base), error);

  return g_tls_connection_apple_bind_base_iostream (base_self,
      g_tls_connection_base_get_base_iostream (tls_base), error);
}
