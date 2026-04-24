/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsserverconnection-apple.h
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "gtlsconnection-apple.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_SERVER_CONNECTION_APPLE            (g_tls_server_connection_apple_get_type ())
#define G_TLS_SERVER_CONNECTION_APPLE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_SERVER_CONNECTION_APPLE, GTlsServerConnectionApple))
#define G_TLS_SERVER_CONNECTION_APPLE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_SERVER_CONNECTION_APPLE, GTlsServerConnectionAppleClass))
#define G_IS_TLS_SERVER_CONNECTION_APPLE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_SERVER_CONNECTION_APPLE))
#define G_IS_TLS_SERVER_CONNECTION_APPLE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_SERVER_CONNECTION_APPLE))
#define G_TLS_SERVER_CONNECTION_APPLE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_SERVER_CONNECTION_APPLE, GTlsServerConnectionAppleClass))

typedef struct _GTlsServerConnectionApple       GTlsServerConnectionApple;
typedef struct _GTlsServerConnectionAppleClass  GTlsServerConnectionAppleClass;

struct _GTlsServerConnectionAppleClass
{
  GTlsConnectionAppleClass parent_class;
};

GType g_tls_server_connection_apple_get_type (void) G_GNUC_CONST;

G_END_DECLS
