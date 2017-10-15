cmake_minimum_required(VERSION 3.8)
project(Skeleton_Code)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        gbn.c
        gbn.h
        receiver.c
        sender.c)

add_executable(Skeleton_Code ${SOURCE_FILES})