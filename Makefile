NAME = netscan

CXX = c++
CXXFLAGS = -Wall -Wextra -std=c++17 -MMD -MP -I include

# Link with Winsock on Windows
ifeq ($(OS),Windows_NT)
    LIBS = -lws2_32
else
    LIBS = 
endif

SRC = models/main.cpp models/scanner.cpp models/honeypot.cpp models/detector.cpp
OBJ = $(SRC:.cpp=.o)
DEP = $(SRC:.cpp=.d)

all: $(NAME)

$(NAME): $(OBJ)
	@$(CXX) $(CXXFLAGS) $(OBJ) -o $(NAME) $(LIBS)

-include $(DEP)

%.o: %.cpp
	@$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	@rm -rf $(OBJ)
	@rm -rf $(DEP)

fclean: clean
	@rm -rf $(NAME)

re: fclean all

.PHONY: all clean fclean re
