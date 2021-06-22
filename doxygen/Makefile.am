if HAVE_DOXYGEN

# Be sure to add new source files to this table
doc_srcs = $(top_srcdir)/src/attr.c     \
           $(top_srcdir)/src/callback.c \
           $(top_srcdir)/src/nlmsg.c    \
           $(top_srcdir)/src/socket.c

doxyfile.stamp: $(doc_srcs) Makefile.am
	rm -rf html man

# Test for running under make distcheck.
# If so, sibling src directory will be empty:
# move it out of the way and symlink the real one while we run doxygen.
	[ -f ../src/Makefile.in ] || \
{ set -x; cd ..; mv src src.distcheck; ln -s $(top_srcdir)/src; }

	cd ..; doxygen doxygen.cfg >/dev/null

	[ ! -d ../src.distcheck ] || \
{ set -x; cd ..; rm src; mv src.distcheck src; }

# Keep this command up to date after adding new functions and source files.
# The command has to be a single line so the functions work
# (hence ";\" at the end of every line but the last).
	main() { set -e; cd man/man3; rm -f _*;\
setgroup attr mnl_attr_get_type;\
  add2group mnl_attr_get_len mnl_attr_get_payload_len mnl_attr_get_payload;\
  add2group mnl_attr_ok mnl_attr_next mnl_attr_type_valid mnl_attr_validate;\
  add2group mnl_attr_validate2 mnl_attr_parse mnl_attr_parse_nested;\
  add2group mnl_attr_parse_payload mnl_attr_get_u8 mnl_attr_get_u16;\
  add2group mnl_attr_get_u32 mnl_attr_get_u64 mnl_attr_get_str mnl_attr_put;\
  add2group mnl_attr_put_u8 mnl_attr_put_u16 mnl_attr_put_u32 mnl_attr_put_u64;\
  add2group mnl_attr_put_str mnl_attr_put_strz mnl_attr_nest_start;\
  add2group mnl_attr_put_check mnl_attr_put_u8_check mnl_attr_put_u16_check;\
  add2group mnl_attr_put_u32_check mnl_attr_put_u64_check;\
  add2group mnl_attr_put_str_check mnl_attr_put_strz_check;\
  add2group mnl_attr_nest_start_check mnl_attr_nest_end mnl_attr_nest_cancel;\
setgroup batch mnl_nlmsg_batch_start;\
  add2group mnl_nlmsg_batch_stop mnl_nlmsg_batch_next mnl_nlmsg_batch_reset;\
  add2group mnl_nlmsg_batch_size mnl_nlmsg_batch_head mnl_nlmsg_batch_current;\
  add2group mnl_nlmsg_batch_is_empty;\
setgroup callback mnl_cb_run;\
  add2group mnl_cb_run2;\
setgroup nlmsg mnl_nlmsg_size;\
  add2group mnl_nlmsg_get_payload_len mnl_nlmsg_put_header;\
  add2group mnl_nlmsg_put_extra_header mnl_nlmsg_get_payload;\
  add2group mnl_nlmsg_get_payload_offset mnl_nlmsg_ok mnl_nlmsg_next;\
  add2group mnl_nlmsg_get_payload_tail mnl_nlmsg_seq_ok mnl_nlmsg_portid_ok;\
  add2group mnl_nlmsg_fprintf;\
setgroup socket mnl_socket_get_fd;\
  add2group mnl_socket_get_portid mnl_socket_open mnl_socket_open2;\
  add2group mnl_socket_fdopen mnl_socket_bind mnl_socket_sendto;\
  add2group mnl_socket_recvfrom mnl_socket_close mnl_socket_setsockopt;\
  add2group mnl_socket_getsockopt;\
};\
setgroup() { mv $$1.3 $$2.3; BASE=$$2; };\
add2group() { for i in $$@; do ln -sf $$BASE.3 $$i.3; done; };\
main

	touch doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/doxygen/man $(top_srcdir)/doxygen/html
install-data-local:
	mkdir -p $(DESTDIR)$(mandir)/man3
	cp --no-dereference --preserve=links,mode,timestamps man/man3/*.3 $(DESTDIR)$(mandir)/man3/

# make distcheck needs uninstall-local
uninstall-local:
	rm -r $(DESTDIR)$(mandir) man html doxyfile.stamp
endif
