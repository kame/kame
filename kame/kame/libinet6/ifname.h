struct if_nameindex {
	unsigned int    if_index;       /* 1, 2, ... */
	char            *if_name;       /* null terminated name: "le0", ... */
};

unsigned int if_nametoindex __P((const char *));
char *if_indextoname __P((unsigned int, char *));
struct if_nameindex *if_nameindex __P((void));
void if_freenameindex __P((struct if_nameindex *));
