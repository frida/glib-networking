/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 * gtlscertificate-apple.h
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

#define G_TYPE_TLS_CERTIFICATE_APPLE            (g_tls_certificate_apple_get_type ())
#define G_TLS_CERTIFICATE_APPLE(inst)           (G_TYPE_CHECK_INSTANCE_CAST ((inst), G_TYPE_TLS_CERTIFICATE_APPLE, GTlsCertificateApple))
#define G_TLS_CERTIFICATE_APPLE_CLASS(class)    (G_TYPE_CHECK_CLASS_CAST ((class), G_TYPE_TLS_CERTIFICATE_APPLE, GTlsCertificateAppleClass))
#define G_IS_TLS_CERTIFICATE_APPLE(inst)        (G_TYPE_CHECK_INSTANCE_TYPE ((inst), G_TYPE_TLS_CERTIFICATE_APPLE))
#define G_IS_TLS_CERTIFICATE_APPLE_CLASS(class) (G_TYPE_CHECK_CLASS_TYPE ((class), G_TYPE_TLS_CERTIFICATE_APPLE))
#define G_TLS_CERTIFICATE_APPLE_GET_CLASS(inst) (G_TYPE_INSTANCE_GET_CLASS ((inst), G_TYPE_TLS_CERTIFICATE_APPLE, GTlsCertificateAppleClass))

typedef struct _GTlsCertificateApple        GTlsCertificateApple;
typedef struct _GTlsCertificateAppleClass   GTlsCertificateAppleClass;

struct _GTlsCertificateAppleClass
{
  GTlsCertificateClass parent_class;
};

GType                 g_tls_certificate_apple_get_type           (void) G_GNUC_CONST;

GTlsCertificate      *g_tls_certificate_apple_new_from_sec       (SecCertificateRef     cert,
                                                                  SecKeyRef             private_key,
                                                                  GTlsCertificate      *issuer);

SecCertificateRef     g_tls_certificate_apple_get_cert           (GTlsCertificateApple *self);
SecKeyRef             g_tls_certificate_apple_get_private_key    (GTlsCertificateApple *self);
SecIdentityRef        g_tls_certificate_apple_copy_identity      (GTlsCertificateApple *self);
gboolean              g_tls_certificate_apple_matches_identity   (GTlsCertificateApple *self,
                                                                  GSocketConnectable   *identity);
CFDataRef             g_tls_certificate_apple_copy_raw_issuer_dn  (SecCertificateRef     cert);
CFDataRef             g_tls_certificate_apple_copy_raw_subject_dn (SecCertificateRef     cert);

G_END_DECLS
