/*
 * This file is part of the KeepKey project.
 *
 * Copyright (C) 2021 Reid Rankin <reidrankin@gmail.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "keepkey/firmware/version.h"
#include "scm_revision.h"

#include <stddef.h>

uint8_t get_major_version(void) {
#ifdef MAJOR_VERSION
  return MAJOR_VERSION;
#else
  return 0;
#endif
}

uint8_t get_minor_version(void) {
#ifdef MINOR_VERSION
  return MINOR_VERSION;
#else
  return 0;
#endif
}

uint8_t get_patch_version(void) {
#ifdef PATCH_VERSION
  return PATCH_VERSION;
#else
  return 0;
#endif
}

const char* get_scm_revision(void) {
#ifdef SCM_REVISION
  return SCM_REVISION;
#else
  return NULL;
#endif
}
