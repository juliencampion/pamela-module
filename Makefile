NAME=	pam_pamela.so

CFLAGS=	-fPIC -Wall -Wextra

SRC=	session.c

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
