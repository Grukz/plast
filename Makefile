TARGET=plast

ENV_PATH=/usr/bin/env
REQUIREMENTS_PATH=./$(TARGET)/REQUIREMENTS

INSTALL_DIR=/usr/local
SYMLINK_DIR=/usr/local/bin
LOG_DIR=/var/log/$(TARGET)

export PATH:=$(SYMLINK_DIR):$(PATH)

.PHONY: install remove

install:
	$(ENV_PATH) pip install -r $(REQUIREMENTS_PATH)
	$(ENV_PATH) rm -rf $(INSTALL_DIR)/$(TARGET)
	$(ENV_PATH) git clone . $(INSTALL_DIR)/$(TARGET)
	$(ENV_PATH) chmod 700 $(INSTALL_DIR)/$(TARGET)/$(TARGET)/$(TARGET).py
	$(ENV_PATH) mkdir $(LOG_DIR)
	$(ENV_PATH) ln -sf $(INSTALL_DIR)/$(TARGET)/$(TARGET)/$(TARGET).py $(SYMLINK_DIR)/$(TARGET)
	@$(ENV_PATH) echo "info: $(TARGET) $(shell git rev-parse HEAD) successfully installed"

remove:
	$(ENV_PATH) rm -f $(SYMLINK_DIR)/$(TARGET)
	$(ENV_PATH) rm -rf $(INSTALL_DIR)/$(TARGET)
	@$(ENV_PATH) echo "info: $(TARGET) successfully removed"
