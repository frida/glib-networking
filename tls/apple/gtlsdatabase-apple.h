/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsdatabase-apple.h
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
#include <Security/Security.h>

G_BEGIN_DECLS

#define G_TYPE_TLS_DATABASE_APPLE            (g_tls_database_apple_get_type ())
#define G_TLS_DATABASE_APPLE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_DATABASE_APPLE, GTlsDatabaseApple))
#define G_TLS_DATABASE_APPLE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_DATABASE_APPLE, GTlsDatabaseAppleClass))
#define G_IS_TLS_DATABASE_APPLE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_DATABASE_APPLE))
#define G_IS_TLS_DATABASE_APPLE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_DATABASE_APPLE))
#define G_TLS_DATABASE_APPLE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_DATABASE_APPLE, GTlsDatabaseAppleClass))

typedef struct _GTlsDatabaseApple        GTlsDatabaseApple;
typedef struct _GTlsDatabaseAppleClass   GTlsDatabaseAppleClass;

struct _GTlsDatabaseApple
{
  GTlsDatabase parent_instance;

  CFMutableArrayRef anchors;
};

struct _GTlsDatabaseAppleClass
{
  GTlsDatabaseClass parent_class;
};

GType                g_tls_database_apple_get_type (void) G_GNUC_CONST;

GTlsDatabaseApple   *g_tls_database_apple_new      (GError **error);

G_END_DECLS
