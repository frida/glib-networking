/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * apple-module.c
 *
 * Copyright (C) 2026 Ole André Vadla Ravnås
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <glib/gi18n-lib.h>
#include <gio/gio.h>

#include "gtlsbackend-apple.h"
#include "visibility.h"

#ifdef GLIB_NETWORKING_STATIC_COMPILATION

#include "gioapple.h"

void
g_io_module_apple_register (void)
{
  g_tls_backend_apple_register (NULL);
}

#else

GLIB_NETWORKING_EXPORT void
g_io_apple_load (GIOModule *module)
{
  gchar *locale_dir;

  g_tls_backend_apple_register (module);

  locale_dir = g_strdup (LOCALE_DIR);

  bindtextdomain (GETTEXT_PACKAGE, locale_dir);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
  g_free (locale_dir);
}

GLIB_NETWORKING_EXPORT void
g_io_apple_unload (GIOModule *module)
{
}

GLIB_NETWORKING_EXPORT gchar **
g_io_apple_query (void)
{
  return g_strsplit (G_TLS_BACKEND_EXTENSION_POINT_NAME, "!", -1);
}

#endif
