
#ifndef ZYREX_EXPORT_H
#define ZYREX_EXPORT_H

#ifdef ZYREX_STATIC_DEFINE
#  define ZYREX_EXPORT
#  define ZYREX_NO_EXPORT
#else
#  ifndef ZYREX_EXPORT
#    ifdef Zyrex_EXPORTS
        /* We are building this library */
#      define ZYREX_EXPORT 
#    else
        /* We are using this library */
#      define ZYREX_EXPORT 
#    endif
#  endif

#  ifndef ZYREX_NO_EXPORT
#    define ZYREX_NO_EXPORT 
#  endif
#endif

#ifndef ZYREX_DEPRECATED
#  define ZYREX_DEPRECATED __declspec(deprecated)
#endif

#ifndef ZYREX_DEPRECATED_EXPORT
#  define ZYREX_DEPRECATED_EXPORT ZYREX_EXPORT ZYREX_DEPRECATED
#endif

#ifndef ZYREX_DEPRECATED_NO_EXPORT
#  define ZYREX_DEPRECATED_NO_EXPORT ZYREX_NO_EXPORT ZYREX_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef ZYREX_NO_DEPRECATED
#    define ZYREX_NO_DEPRECATED
#  endif
#endif

#endif /* ZYREX_EXPORT_H */
