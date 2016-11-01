NAME=	pam_pamela.so

CFLAGS=	-std=c99 -fPIC -Wall -Wextra

SRC=	common.c \
	session.c

OBJ=	$(SRC:.c=.o)

RM=	rm -f

all:	$(NAME)

$(NAME):	$(OBJ)
	$(CC) -shared -o $(NAME) $(OBJ) -lpam

clean:
	$(RM) $(OBJ)

fclean:	clean
	$(RM) $(NAME)

re:	clean fclean all

.PHONY:	all clean fclean re
