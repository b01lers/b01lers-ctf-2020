#include "rr_crossing.h"
#include <sys/ptrace.h>
struct valmap * maphead;


void a_callback(GSimpleAction * simple, GVariant * parameter, gpointer user_data) {
	if (gtk_switch_get_active(GTK_SWITCH(simple))) {
		gtk_label_set_text(GTK_LABEL(user_data), "1");
		set_mapval_b(maphead, gtk_widget_get_name(GTK_WIDGET(simple)), true);
	} else {
		gtk_label_set_text(GTK_LABEL(user_data), "0");
		set_mapval_b(maphead, gtk_widget_get_name(GTK_WIDGET(simple)), false);
	}
}

void combo_callback(GSimpleAction * simple, GVariant * parameter, gpointer user_data) {
	gchar * text = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(simple));
	if (text != NULL) {
		set_mapval_c(maphead, gtk_widget_get_name(GTK_WIDGET(simple)), text[0]);
	}
}

void slider_callback(GSimpleAction * simple, GVariant * parameter, gpointer user_data) {
	GtkAdjustment * adj = gtk_range_get_adjustment(GTK_RANGE(simple));
	gdouble value = gtk_adjustment_get_value(GTK_ADJUSTMENT(adj));
	set_mapval_i(maphead, gtk_widget_get_name(GTK_WIDGET(simple)), (int64_t)value);
}

void random_callback(GSimpleAction * simple, GVariant * parameter, gpointer user_data) {
	char c[2] = {(rand() % 0x5e) + 0x20, 0};
	gtk_button_set_label(GTK_BUTTON(simple), c);
	set_mapval_c(maphead, gtk_widget_get_name(GTK_WIDGET(simple)), c[0]);
}

void submit_callback(GSimpleAction * simple, GVariant * parameter, gpointer user_data) {
	destroy_map(maphead);
	struct valmap * head = maphead;
	while (head->next) {
		printf("%lx\n", (long)head + sizeof(struct valmap *) + sizeof(char *));
		head = head->next;
	}
}

void destroy_callback(GSimpleAction * simple, GVariant * parameter, gpointer user_data) {
	gtk_main_quit();
	return;
}

void destroy_map(struct valmap * root) {
	struct valmap * head = root;
	while (head->next) {
		char * oof = (char *)head + sizeof(struct valmap *) + sizeof(char *);
		for (unsigned int i = 0; i < sizeof(struct valmap) - sizeof(char *) - sizeof(struct valmap *); i++) {
			*oof++ = rand() % 0xff;
		}
		head = head->next;
	}
}

void set_mapval_b(struct valmap * root, const char * name, bool value) {
	struct valmap * head = root;
	while (head->next) {
		if (head->name != NULL && strcmp(head->name, name) == 0) {
			head->bval = value;
			return;
		}
		head = head->next;
	}
}

void set_mapval_c(struct valmap * root, const char * name, char value) {
	struct valmap * head = root;
	while (head->next) {
		if (head->name != NULL && strcmp(head->name, name) == 0) {
			head->cval = value;
			return;
		}
		head = head->next;
	}
}

void set_mapval_i(struct valmap * root, const char * name, int64_t value) {
	struct valmap * head = root;
	while (head->next) {
		if (head->name != NULL && strcmp(head->name, name) != 0) {
			head->ival = value;
			return;
		}
		head = head->next;
	}
}

struct valmap * init_valmap(void) {
	struct valmap * p = (struct valmap *)malloc(sizeof(struct valmap));
	p->next = NULL;
	p->name = NULL;
}

bool map_hasname(struct valmap * root, const char * find) {
	struct valmap * head = root;
	while (head->next) {
		if (head->name != NULL && strcmp(head->name, find) == 0) {
			return true;
		}
		head = head->next;
	}
	return false;
}

void map_add(struct valmap * root, const char * name) {
	struct valmap * head = root;
	while (head->next) {
		head = head->next;
	}
	struct valmap * new = init_valmap();
	new->name = strdup(name);
	head->next = new;
}

void populate_passcode_maps(GtkWidget * widget, gpointer user_data) {
	struct valmap * root = (struct valmap *)user_data;
	const gchar * name = gtk_widget_get_name (GTK_WIDGET(widget));
	if (!map_hasname(root, name)) {
		map_add(root, name);
	}
}

int init_app(GtkApplication * app, int argc, char ** argv) {
	printf("Initializing app\n");
	srand(time(NULL));
	struct valmap * root = init_valmap();
	maphead = root;
	gtk_init(&argc, &argv);
	printf("Initialized app\n");
	GtkBuilder * builder = gtk_builder_new();
	gtk_builder_add_from_string(builder, gladefile, -1, NULL);
	//gtk_builder_add_from_file(builder, "rr_crossing.glade", NULL);
	GtkWidget * window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
	gtk_builder_connect_signals(builder, NULL);
	gtk_container_foreach(GTK_CONTAINER(gtk_builder_get_object(builder, "grid")), (GtkCallback)populate_passcode_maps, root);
	gtk_widget_show(window);
	gtk_main();
	return 0;
}

int main(int argc, char ** argv) {
	printf("Starting Railroad Crossing\n");
	//ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	//raise(SIGSTOP);
	printf("Running Railroad Crossing\n");
	GtkApplication * app = NULL;
	init_app(app, argc, argv);
}

