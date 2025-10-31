# Copyright (c) 2022 Microchip Technology Inc. and its subsidiaries.
# SPDX-License-Identifier: (GPL-2.0)

cmake_minimum_required(VERSION 2.6)
project (otp C)

SET(VER "0.1")

add_definitions(-Wall)
add_definitions(-DVER=\"${VER}\")

add_executable(otp otp.c)

install(TARGETS otp RUNTIME DESTINATION bin)
