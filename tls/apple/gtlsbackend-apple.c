/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlsbackend-apple.c
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

#include "gtlsbackend-apple.h"
#include "gtlscertificate-apple.h"
#include "gtlsclientconnection-apple.h"
#include "gtlsserverconnection-apple.h"
#include "gtlsfiledatabase-apple.h"
#include "gtlsdatabase-apple.h"

struct _GTlsBackendApple
{
  GObject parent_instance;

  GMutex mutex;
  GTlsDatabase *default_database;
};

static void          g_tls_backend_apple_dispose               (GObject *object);
static void          g_tls_backend_apple_finalize              (GObject *object);
static void          g_tls_backend_apple_interface_init        (GTlsBackendInterface *iface);
static GTlsDatabase *g_tls_backend_apple_get_default_database  (GTlsBackend *backend);

G_DEFINE_DYNAMIC_TYPE_EXTENDED (GTlsBackendApple, g_tls_backend_apple, G_TYPE_OBJECT, 0,
                                G_IMPLEMENT_INTERFACE_DYNAMIC (G_TYPE_TLS_BACKEND,
                                                               g_tls_backend_apple_interface_init))

static void
g_tls_backend_apple_class_init (GTlsBackendAppleClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->dispose  = g_tls_backend_apple_dispose;
  gobject_class->finalize = g_tls_backend_apple_finalize;
}

static void
g_tls_backend_apple_class_finalize (GTlsBackendAppleClass *backend_class)
{
}

static void
g_tls_backend_apple_init (GTlsBackendApple *backend)
{
  g_mutex_init (&backend->mutex);
}

static void
g_tls_backend_apple_dispose (GObject *object)
{
  GTlsBackendApple *backend = G_TLS_BACKEND_APPLE (object);

  g_clear_object (&backend->default_database);

  G_OBJECT_CLASS (g_tls_backend_apple_parent_class)->dispose (object);
}

static void
g_tls_backend_apple_finalize (GObject *object)
{
  GTlsBackendApple *backend = G_TLS_BACKEND_APPLE (object);

  g_mutex_clear (&backend->mutex);

  G_OBJECT_CLASS (g_tls_backend_apple_parent_class)->finalize (object);
}

static void
g_tls_backend_apple_interface_init (GTlsBackendInterface *iface)
{
  iface->get_certificate_type = g_tls_certificate_apple_get_type;
  iface->get_client_connection_type = g_tls_client_connection_apple_get_type;
  iface->get_server_connection_type = g_tls_server_connection_apple_get_type;
  iface->get_file_database_type = g_tls_file_database_apple_get_type;
  iface->get_default_database = g_tls_backend_apple_get_default_database;
  iface->get_dtls_client_connection_type = g_tls_client_connection_apple_get_type;
  iface->get_dtls_server_connection_type = g_tls_server_connection_apple_get_type;
}

static GTlsDatabase *
g_tls_backend_apple_get_default_database (GTlsBackend *backend)
{
  GTlsBackendApple *apple_backend = G_TLS_BACKEND_APPLE (backend);
  GTlsDatabase *result;
  GError *error = NULL;

  g_mutex_lock (&apple_backend->mutex);

  if (apple_backend->default_database)
    {
      result = g_object_ref (apple_backend->default_database);
    }
  else
    {
      result = G_TLS_DATABASE (g_tls_database_apple_new (&error));
      if (error)
        {
          g_warning ("Couldn't load default TLS database: %s",
                     error->message);
          g_clear_error (&error);
        }
      else
        {
          g_assert (result);
          apple_backend->default_database = g_object_ref (result);
        }
    }

  g_mutex_unlock (&apple_backend->mutex);

  return result;
}

void
g_tls_backend_apple_register (GIOModule *module)
{
  g_tls_backend_apple_register_type (G_TYPE_MODULE (module));
  if (!module)
    g_io_extension_point_register (G_TLS_BACKEND_EXTENSION_POINT_NAME);
  g_io_extension_point_implement (G_TLS_BACKEND_EXTENSION_POINT_NAME,
                                  g_tls_backend_apple_get_type (),
                                  "apple",
                                  -1);
}
