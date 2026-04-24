/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsconnection-apple.h
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "gtlsconnection-base.h"
#include <Security/Security.h>
#include <Network/Network.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_CONNECTION_APPLE            (g_tls_connection_apple_get_type ())
#define G_TLS_CONNECTION_APPLE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CONNECTION_APPLE, GTlsConnectionApple))
#define G_TLS_CONNECTION_APPLE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CONNECTION_APPLE, GTlsConnectionAppleClass))
#define G_IS_TLS_CONNECTION_APPLE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CONNECTION_APPLE))
#define G_IS_TLS_CONNECTION_APPLE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CONNECTION_APPLE))
#define G_TLS_CONNECTION_APPLE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CONNECTION_APPLE, GTlsConnectionAppleClass))

typedef struct _GTlsConnectionApple       GTlsConnectionApple;
typedef struct _GTlsConnectionAppleClass  GTlsConnectionAppleClass;

struct _GTlsConnectionAppleClass
{
  GTlsConnectionBaseClass parent_class;

  gboolean (*start_handshake) (GTlsConnectionApple  *self,
                               GError              **error);
};

struct _GTlsConnectionApple
{
  GTlsConnectionBase parent_instance;
};

GType                 g_tls_connection_apple_get_type (void) G_GNUC_CONST;

gboolean              g_tls_connection_apple_bind_base_iostream (GTlsConnectionApple *self,
                                                                  GIOStream           *base,
                                                                  GError             **error);
gboolean              g_tls_connection_apple_bind_base_socket    (GTlsConnectionApple *self,
                                                                  GDatagramBased      *base,
                                                                  GError             **error);
int                   g_tls_connection_apple_setup_bounce_transport
                                                                 (GTlsConnectionApple *self,
                                                                  GError             **error);
void                  g_tls_connection_apple_release_bounce_fd
                                                                 (GTlsConnectionApple *self,
                                                                  int                  apple_fd);
void                  g_tls_connection_apple_install_verify_block
                                                                 (GTlsConnectionApple   *self,
                                                                  sec_protocol_options_t options);
void                  g_tls_connection_apple_add_advertised_protocols
                                                                 (GTlsConnection        *tls,
                                                                  sec_protocol_options_t options);
void                  g_tls_connection_apple_attach             (GTlsConnectionApple *self,
                                                                  nw_connection_t      connection);
nw_connection_t       g_tls_connection_apple_get_nw_connection (GTlsConnectionApple *self);
dispatch_queue_t      g_tls_connection_apple_get_queue         (GTlsConnectionApple *self);

G_END_DECLS
