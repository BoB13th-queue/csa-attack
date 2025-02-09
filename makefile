# Makefile

CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++11
LDFLAGS  = -lpcap

# 실행 파일 이름(경로 포함)
TARGET   = bin/csa-attack

# 디렉터리 설정
SRC_DIR  = src
OBJ_DIR  = object
INC_DIR  = include

# 빌드할 소스 파일 목록
SRCS = $(SRC_DIR)/*.cpp

# 오브젝트 파일 목록
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# make 기본 타겟
all: $(TARGET)

# 최종 실행 파일 만들기
$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# 소스 -> 오브젝트 빌드 규칙
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) -c $< -o $@

# clean: 빌드 산출물 제거
clean:
	rm -f $(OBJ_DIR)/*.o
	rm -f $(TARGET)

.PHONY: all clean
