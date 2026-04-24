/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsfiledatabase-apple.h
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include "gtlsdatabase-apple.h"

G_BEGIN_DECLS

#define G_TYPE_TLS_FILE_DATABASE_APPLE            (g_tls_file_database_apple_get_type ())
#define G_TLS_FILE_DATABASE_APPLE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_FILE_DATABASE_APPLE, GTlsFileDatabaseApple))
#define G_TLS_FILE_DATABASE_APPLE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_FILE_DATABASE_APPLE, GTlsFileDatabaseAppleClass))
#define G_IS_TLS_FILE_DATABASE_APPLE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_FILE_DATABASE_APPLE))
#define G_IS_TLS_FILE_DATABASE_APPLE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_FILE_DATABASE_APPLE))
#define G_TLS_FILE_DATABASE_APPLE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_FILE_DATABASE_APPLE, GTlsFileDatabaseAppleClass))

typedef struct _GTlsFileDatabaseApple       GTlsFileDatabaseApple;
typedef struct _GTlsFileDatabaseAppleClass  GTlsFileDatabaseAppleClass;

struct _GTlsFileDatabaseAppleClass
{
  GTlsDatabaseAppleClass parent_class;
};

GType g_tls_file_database_apple_get_type (void) G_GNUC_CONST;

G_END_DECLS
