/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsbackend-apple.h
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <gio/gio.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_BACKEND_APPLE            (g_tls_backend_apple_get_type ())
#define G_TLS_BACKEND_APPLE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_BACKEND_APPLE, GTlsBackendApple))
#define G_TLS_BACKEND_APPLE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_BACKEND_APPLE, GTlsBackendAppleClass))
#define G_IS_TLS_BACKEND_APPLE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_BACKEND_APPLE))
#define G_IS_TLS_BACKEND_APPLE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_BACKEND_APPLE))
#define G_TLS_BACKEND_APPLE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_BACKEND_APPLE, GTlsBackendAppleClass))

typedef struct _GTlsBackendApple        GTlsBackendApple;
typedef struct _GTlsBackendAppleClass   GTlsBackendAppleClass;

struct _GTlsBackendAppleClass
{
  GObjectClass parent_class;
};

GType g_tls_backend_apple_get_type (void) G_GNUC_CONST;

void  g_tls_backend_apple_register (GIOModule *module);

G_END_DECLS
