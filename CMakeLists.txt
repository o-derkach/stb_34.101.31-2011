cmake_minimum_required(VERSION 2.8)	 # Проверка версии CMake.

project(STB_34.101.31)			# Название проекта

aux_source_directory("Src/cipher"	SRC_DIRS)
aux_source_directory("Src/utils" 	SRC_DIRS)
aux_source_directory("Src" 		SRC_DIRS)

set(HEADER_FILES "Inc")			# Тоже самое, но для библиотеки

#set(EXTRA_LIBS crypto)

include_directories(${HEADER_FILES})

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O3")

add_executable(main ${SRC_DIRS})	# Создает исполняемый файл с именем main

find_library(M_LIB m)

target_link_libraries(main ${M_LIB})
