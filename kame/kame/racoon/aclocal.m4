dnl RACOON_PATH_LIBS(FUNCTION, LIB, SEARCH-PATHS [, ACTION-IF-FOUND
dnl            [, ACTION-IF-NOT-FOUND [, OTHER-LIBRARIES]]])
dnl Search for a library defining FUNC, if it's not already available.

AC_DEFUN(RACOON_PATH_LIBS,
[AC_PREREQ([2.13])
AC_CACHE_CHECK([for $2 containing $1], [ac_cv_search_$1],
[ac_func_search_save_LIBS="$LIBS"
ac_cv_search_$1="no"
AC_TRY_LINK_FUNC([$1], [ac_cv_search_$1="none required"],
	[LIBS="-l$2 $LIBS"
	AC_TRY_LINK_FUNC([$1], [ac_cv_search_$1="-l$2"], [])])
LIBS="$ac_func_search_save_LIBS"
test "$ac_cv_search_$1" = "no" && for i in $3; do
LIBS="-L$i -l$2 $ac_func_search_save_LIBS"
AC_TRY_LINK_FUNC([$1],
[ac_cv_search_$1="-L$i -l$2"
break])
done
LIBS="$ac_func_search_save_LIBS"])
if test "$ac_cv_search_$1" != "no"; then
  test "$ac_cv_search_$1" = "none required" || LIBS="$ac_cv_search_$1 $LIBS"
  $4
else :
  $5
fi])

AC_DEFUN(RACOON_SEARCH_HEADER,
[AC_PREREQ([2.13])
AC_MSG_CHECKING(for $1)
AC_TRY_CPP([#include <$1>], [], [
ac_func_search_save_CPPFLAGS="$CPPFLAGS"
ac_add_path="no"
for i in $2; do
	CPPFLAGS="-I$i $CPPFLAGS"
	AC_TRY_CPP([#include <$1>],
		[ac_add_path=$i])
	CPPFLAGS="$ac_func_search_save_CPPFLAGS"
	if test "$ac_add_path" != "no"; then
		break
	fi
done
if test "$ac_add_path" != "no"; then
	CPPFLAGS="-I$ac_add_path $CPPFLAGS"
fi
AC_MSG_RESULT($ac_add_path)
])])
