# $Id: Makefile,v 1.1 1999/10/07 16:35:24 itojun Exp $

SUBDIR += security

PORTSTOP?=	yes

.include <bsd.port.subdir.mk>

index:
	@rm -f ${.CURDIR}/INDEX
	@make ${.CURDIR}/INDEX

${.CURDIR}/INDEX:
	@echo -n "Generating INDEX - please wait.."
	@make describe ECHO_MSG="echo > /dev/null" > ${.CURDIR}/INDEX
	@echo " Done."

print-index:	${.CURDIR}/INDEX
	@awk -F\| '{ printf("Port:\t%s\nPath:\t%s\nInfo:\t%s\nMaint:\t%s\nIndex:\t%s\nB-deps:\t%s\nR-deps:\t%s\n\n", $$1, $$2, $$4, $$6, $$7, $$8, $$9); }' < ${.CURDIR}/INDEX

search:	${.CURDIR}/INDEX
.if !defined(key)
	@echo "The search target requires a keyword parameter,"
	@echo "e.g.: \"make search key=somekeyword\""
.else
	@grep -i ${key} ${.CURDIR}/INDEX | awk -F\| '{ printf("Port:\t%s\nPath:\t%s\nInfo:\t%s\nMaint:\t%s\nIndex:\t%s\nB-deps:\t%s\nR-deps:\t%s\nArchs:\t%s\n\n", $$1, $$2, $$4, $$6, $$7, $$8, $$9, $$10); }'
.endif
