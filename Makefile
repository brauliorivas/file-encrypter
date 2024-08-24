CC := gcc
NAME := encrypter
LIB := lib
SRC := src
INCLUDE := include
BUILD := build
BIN := bin
TARGET := $(BIN)/$(NAME)
LIBS := $(wildcard $(LIB)/**/*.c)
HEADER_FILES := $(wildcard $(INCLUDE)/*.h)
SRC_FILES := $(wildcard $(SRC)/*.c)
OBJS := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SRC_FILES))
SLIBS := $(patsubst %.c,$(BUILD)/$(LIB)/%.a,$(notdir $(LIBS)))
SLIBS_OBJS := $(patsubst %.a,%.o,$(SLIBS))
INCLUDE_DIRS := $(foreach d,$(INCLUDE) $(wildcard $(LIB)/*),-I$d)

$(TARGET): $(SLIBS) $(OBJS) | $(BUILD) $(BIN)
	$(CC) -static -o $(TARGET) $(OBJS) $(SLIBS)

$(OBJS): $(SRC_FILES) $(HEADER_FILES) | $(BUILD)
	$(CC) -c $(SRC)/$(patsubst %.o,%.c,$(@F)) $(INCLUDE_DIRS) -o $@

$(SLIBS): $(SLIBS_OBJS)
	ar rcs $@ $(BUILD)/$(LIB)/$(patsubst %.a,%.o,$(@F))
 
$(SLIBS_OBJS): $(LIBS) | $(BUILD) 
	$(CC) -c $(LIB)/$(patsubst %.o,%,$(@F))/$(patsubst %.o,%.c,$(@F)) -o $@

$(BUILD):
	@mkdir $(BUILD) 
	@mkdir $(BUILD)/$(LIB)

$(BIN):
	@mkdir $(BIN)

clean:
	rm -rf $(BUILD) $(BIN)

.PHONY: clean
