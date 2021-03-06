/*
 *  This file is part of the optimized implementation of the Picnic signature scheme.
 *  See the accompanying documentation for complete details.
 *
 *  The code is provided under the MIT license, see LICENSE for
 *  more details.
 *  SPDX-License-Identifier: MIT
 */

#ifndef PICNIC_MACROS_H
#define PICNIC_MACROS_H

/* compatibility with clang and other compilers */
#ifndef __has_attribute
#define __has_attribute(a) 0
#endif

#ifndef __has_builtin
#define __has_builtin(b) 0
#endif

/* gcc version check macro */
#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define GNUC_CHECK(maj, min)                                                                       \
  (((__GNUC__ << 20) + (__GNUC_MINOR__ << 10)) >= (((maj) << 20) + ((min) << 10)))
#else
#define GNUC_CHECK(maj, min) 0
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* nonnull attribute */
#if GNUC_CHECK(3, 3) || __has_attribute(nonnull)
#define ATTR_NONNULL __attribute__((nonnull))
#define ATTR_NONNULL_ARG(i) __attribute__((nonnull(i)))
#else
#define ATTR_NONNULL
#define ATTR_NONNULL_ARG(i)
#endif

/* destructor attribute */
#if GNUC_CHECK(2, 7) || __has_attribute(destructor)
#define ATTR_DTOR __attribute__((destructor))
#else
#define ATTR_DTOR
#endif

/* assumed aligned attribute */
#if GNUC_CHECK(4, 9) || __has_attribute(assume_aligned)
#define ATTR_ASSUME_ALIGNED(i) __attribute__((assume_aligned(i)))
#else
#define ATTR_ASSUME_ALIGNED(i)
#endif

/* aligned attribute */
/* note that C11's alignas will only do the job once DR 444 is implemented */
#if GNUC_CHECK(4, 9) || __has_attribute(aligned)
#define ATTR_ALIGNED(i) __attribute__((aligned((i))))
/* #elif defined(_MSC_VER)
#define ATTR_ALIGNED(i) __declspec(align((i))) */
#else
#define ATTR_ALIGNED(i)
#endif

/* unreachable builtin */
#if GNUC_CHECK(4, 5) || __has_builtin(__builtin_unreachable)
#define UNREACHABLE __builtin_unreachable()
/* #elif defined(_MSC_VER)
#define UNREACHABLE __assume(0) */
#endif

/* assume aligned builtin */
#if GNUC_CHECK(4, 9) || __has_builtin(__builtin_assume_aligned)
#define ASSUME_ALIGNED(p, a) __builtin_assume_aligned((p), (a))
#elif defined(UNREACHABLE)
#define ASSUME_ALIGNED(p, a) (((((uintptr_t)(p)) % (a)) == 0) ? (p) : (UNREACHABLE, (p)))
#else
#define ASSUME_ALIGNED(p, a) (p)
#endif

/* always inline attribute */
#if GNUC_CHECK(4, 0) || __has_attribute(always_inline)
#define ATTR_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
#define ATTR_ALWAYS_INLINE __forceinline
#else
#define ATTR_ALWAYS_INLINE
#endif

/* pure attribute */
#if defined(__GNUC__) || __has_attribute(pure)
#define ATTR_PURE __attribute__((pure))
#else
#define ATTR_PURE
#endif

/* target attribute */
#if defined(__GNUC__) || __has_attribute(target)
#define ATTR_TARGET(x) __attribute__((target((x))))
#else
#define ATTR_TARGET(x)
#endif

#define FN_ATTRIBUTES_AVX2_NP ATTR_ALWAYS_INLINE ATTR_TARGET("avx2")
#define FN_ATTRIBUTES_SSE2_NP ATTR_ALWAYS_INLINE ATTR_TARGET("sse2")
#define FN_ATTRIBUTES_NEON_NP ATTR_ALWAYS_INLINE

#define FN_ATTRIBUTES_AVX2 FN_ATTRIBUTES_AVX2_NP ATTR_PURE
#define FN_ATTRIBUTES_SSE2 FN_ATTRIBUTES_SSE2_NP ATTR_PURE
#define FN_ATTRIBUTES_NEON FN_ATTRIBUTES_NEON_NP ATTR_PURE

/* concatenation */
#define CONCAT2(a, b) a##_##b
#define CONCAT(a, b) CONCAT2(a, b)

/* helper macros to select matrices and multiplicatiion functions */
#if defined(MUL_M4RI)
#define matrix_postfix lookup
#else
#define matrix_postfix matrix
#endif

#if defined(MUL_M4RI)
#define SELECT_V_VL(v, vl) vl
#else
#define SELECT_V_VL(v, vl) v
#endif

/* helper to select lowmc implementations */
#if defined(WITH_CUSTOM_INSTANCES)
#define general_or_10(l, f) (l)->m == 10 ? f##_10 : (f)
#else
#define general_or_10(l, f) f##_10
#define general_or_1(l, f) f##_1
#endif

/* helper macros/functions for checked integer subtraction */
#if GNUC_CHECK(5, 0) || __has_builtin(__builtin_add_overflow)
#define sub_overflow_size_t(x, y, diff) __builtin_sub_overflow(x, y, diff)
#else
#include <stdbool.h>
#include <stddef.h>

static inline bool sub_overflow_size_t(const size_t x, const size_t y, size_t* diff) {
  *diff = x - y;
  return x < y;
}
#endif

#endif
