/* gf256.h - interface to arithmetic operations in GF(256)
 *
 * Copyright 2020 Rik Snel <rik@snel.it>
 *
 * This file is part of slip0039.
 *
 * slip0039 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * slip0039 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with slip0039.  If not, see <https://www.gnu.org/licenses/>.
 */
#ifndef SLIP0039_GF256_H
#define SLIP0039_GR256_H
#include <stdint.h>

uint8_t gf256_add(uint8_t, uint8_t);

uint8_t gf256_inv(uint8_t);

uint8_t gf256_mul(uint8_t, uint8_t);

uint8_t gf256_div(uint8_t, uint8_t);

#endif /* SLIP0039_GF256_H */
