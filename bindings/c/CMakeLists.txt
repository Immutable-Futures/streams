cmake_minimum_required(VERSION 3.12.0)
project(iota_streams_c LANGUAGES C)

include(FetchContent)

option(IOTA_CLIENT "Enable transport via iota_client" ON)
option(STATIC "Build static library" OFF)
option(RELEASE "Build release library (defaults to release)" ON)

set(cargo_features "")

if(${IOTA_CLIENT})
  add_definitions(-DIOTA_STREAMS_CHANNELS_CLIENT)
  set(cargo_features "${cargo_features}uclient")
endif(${IOTA_CLIENT})


message("IOTA_CLIENT=${IOTA_CLIENT} STATIC=${STATIC} RELEASE=${RELEASE}")

include_directories(include/)

if(${STATIC})
  FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/AndrewGaspar/corrosion.git
    GIT_TAG origin/master # Optionally specify a version tag or branch here
  )

  FetchContent_MakeAvailable(Corrosion)

  corrosion_import_crate(MANIFEST_PATH Cargo.toml)

  add_executable(iota_streams_c_static main.c)
  target_link_libraries(iota_streams_c_static PUBLIC iota_streams_c)

else(${STATIC})
  add_executable(${PROJECT_NAME} main.c)
  message(${cargo_features})

  if(${RELEASE})
    message("Building Release")
    set(BUILD_FLAG --release)
    set(BUILD_LOCATION release)
  else(${RELEASE})
    message("Building Debug")
    set(BUILD_FLAG)
    set(BUILD_LOCATION debug)
  endif(${RELEASE})

  if (WIN32)
    message("Windows")
    add_custom_command(TARGET ${PROJECT_NAME} PRE_BUILD COMMAND dir COMMAND cargo build ${BUILD_FLAG} --target-dir ../../target --no-default-features --features "${cargo_features}" COMMAND copy /Y ..\\..\\target\\${BUILD_LOCATION}\\iota_streams_c.dll .  COMMAND dir)
    target_link_libraries(${PROJECT_NAME} ${PROJECT_SOURCE_DIR}/../../target/release/iota_streams_c.dll)
  elseif (UNIX)
    message("Unix")
    if (APPLE)
      set(SHARED_OBJECT_FILE libiota_streams_c.dylib)
    else (APPLE)
      set(SHARED_OBJECT_FILE libiota_streams_c.so)
    endif (APPLE)
    set(FAKE_TARGET fakeTarget)
    add_custom_target(fakeTarget cargo build ${BUILD_FLAG} --target-dir ../../target --no-default-features --features "${cargo_features}" COMMAND cp ../../target/${BUILD_LOCATION}/${SHARED_OBJECT_FILE} ${CMAKE_CURRENT_SOURCE_DIR})
    add_dependencies(${PROJECT_NAME} ${FAKE_TARGET})

    target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/${SHARED_OBJECT_FILE})
  endif (WIN32)


endif()

unset(NO_STD CACHE)
unset(IOTA_CLIENT CACHE)
unset(STATIC CACHE)
unset(RELEASE CACHE)
