dnl $Id: check_openssl.m4,v 1.2 2006-03-27 07:22:54 jklowden Exp $
# OpenSSL check

AC_DEFUN([CHECK_OPENSSL],
[AC_MSG_CHECKING(if openssl is wanted)
AC_ARG_WITH(openssl, AS_HELP_STRING([--with-openssl], [--with-openssl=DIR build with OpenSSL (license NOT compatible cf. User Guide)]))
if test "$with_openssl" != "no" -a "$cross_compiling" != "yes"; then
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES(OPENSSL, [openssl], [found_ssl=yes
CFLAGS="$CFLAGS $OPENSSL_CFLAGS"
NETWORK_LIBS="$NETWORK_LIBS $OPENSSL_LIBS"], [found_ssl=no
    for dir in $withval /usr/local/ssl /usr/lib/ssl /usr/ssl /usr/pkg /usr/local /usr; do
        ssldir="$dir"
        if test -f "$dir/include/openssl/ssl.h"; then
            echo "OpenSSL found in $ssldir"
            found_ssl="yes"
            CFLAGS="$CFLAGS -I$ssldir/include"
            NETWORK_LIBS="$NETWORK_LIBS -lssl -lcrypto"
            LDFLAGS="$LDFLAGS -L$ssldir/lib"
            break
        fi
    done])
    if test x$found_ssl != xyes; then
        AC_MSG_ERROR(Cannot find OpenSSL libraries)
    else
        HAVE_OPENSSL=yes
        AC_DEFINE(HAVE_OPENSSL, 1, [Define if you have the OpenSSL.])
    fi
    AC_SUBST(HAVE_OPENSSL)
else
    AC_MSG_RESULT(no)
fi
])
