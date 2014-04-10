XMLS=gen_copyright.xml gen_chipsets.xml gen_isa.xml gen_regs.xml gen_mi.xml gen_blitter.xml gen_render_dynamic.xml gen_render_surface.xml gen_render_3d.xml root.xml
HEADERS=$(subst .xml,.xml.h,$(XMLS))

all: $(HEADERS)

$(HEADERS): $(XMLS)
	RNN_PATH=`pwd` ../rnn/headergen $(basename $@)

clean:
	rm -f *.h
