cmake_minimum_required(VERSION 3.25)
project(binja_binexport LANGUAGES C CXX)
include(CTest)
if(NOT APPLE OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
  message(FATAL_ERROR "The export helper currently targets Apple Silicon macOS")
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(HEADLESS ON) # SDK build excludes Qt; runtime still requires the BN GUI.
include(FetchContent)
FetchContent_Declare(bnapi
  GIT_REPOSITORY https://github.com/Vector35/binaryninja-api.git
  GIT_TAG 2ddf304b3275aa184e95570404539cbc4beb64c6 # stable/6.0.10601, ABI 187
  GIT_SUBMODULES vendor/fmt vendor/binexport
  GIT_SUBMODULES_RECURSE OFF)
FetchContent_MakeAvailable(bnapi)
set(BINEXPORT_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BINEXPORT_ENABLE_IDAPRO OFF CACHE BOOL "" FORCE)
set(BINEXPORT_ENABLE_BINARYNINJA OFF CACHE BOOL "" FORCE)
add_subdirectory("${bnapi_SOURCE_DIR}/vendor/binexport" binexport EXCLUDE_FROM_ALL)
add_library(binja_binexport SHARED helper.cpp processor.cpp)
target_include_directories(binja_binexport PRIVATE
  "${bnapi_SOURCE_DIR}/plugins/bindiff_similarity")
target_link_libraries(binja_binexport PRIVATE binaryninjaapi binexport_core)
if(BUILD_TESTING)
  add_executable(binja_binexport_clrbhb_test clrbhb_test.cpp)
  add_test(NAME binja_binexport_clrbhb COMMAND binja_binexport_clrbhb_test)
endif()
target_link_options(binja_binexport PRIVATE
  "LINKER:-exported_symbol,_BNMCPExportABI"
  "LINKER:-exported_symbol,_BNMCPCoreABI"
  "LINKER:-exported_symbol,_BNMCPExportView"
  "LINKER:-exported_symbol,_BNMCPFree")
install(TARGETS binja_binexport LIBRARY DESTINATION binja_windbg_mcp/native)
install(FILES "${bnapi_SOURCE_DIR}/LICENSE.txt" DESTINATION binja_windbg_mcp/native/licenses RENAME binaryninja.txt)
install(FILES "${bnapi_SOURCE_DIR}/vendor/binexport/LICENSE" DESTINATION binja_windbg_mcp/native/licenses RENAME binexport.txt)
install(FILES "${bnapi_SOURCE_DIR}/vendor/fmt/LICENSE" DESTINATION binja_windbg_mcp/native/licenses RENAME fmt.txt)
install(FILES "${absl_SOURCE_DIR}/LICENSE" DESTINATION binja_windbg_mcp/native/licenses RENAME abseil.txt)
install(FILES "${protobuf_SOURCE_DIR}/LICENSE" DESTINATION binja_windbg_mcp/native/licenses RENAME protobuf.txt)
install(FILES "${protobuf_SOURCE_DIR}/third_party/utf8_range/LICENSE" DESTINATION binja_windbg_mcp/native/licenses RENAME utf8_range.txt)
install(FILES BOOST_LICENSE_1_0.txt DESTINATION binja_windbg_mcp/native/licenses)
