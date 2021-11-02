#ifndef OPENOCD_TARGET_ROALOGIC_JSP_SERVER_H
#define OPENOCD_TARGET_ROALOGIC_JSP_SERVER_H

#include "rl_tap.h"
#include "rvl.h"
#include "rl_dbg_adv.h"

struct jsp_service {
	char *banner;
	struct rl_jtag *jtag_info;
	struct connection *connection;
};

int jsp_init(struct rl_jtag *jtag_info, char *banner);
int jsp_register_commands(struct command_context *cmd_ctx);
void jsp_service_free(void);

#endif /* OPENOCD_TARGET_ROALOGIC_JSP_SERVER_H */
