#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>

MODULE_AUTHOR("Aman");
MODULE_DESCRIPTION("This module when inserted causes null pointer dereference fault");
MODULE_LICENSE("GPL");

typedef struct ABC {
  int a;
  int b;
} ABC;

ABC* ptr;

void print(ABC* abc) {
    printk(KERN_INFO "abc(a: %d, b: %d)\n", abc->a, abc->b);
}

void cause_gpf(void) {
    printk(KERN_WARNING "Hello World <Insert Evil Laughter>\n\n");
    ptr = kmalloc(sizeof(ABC), GFP_KERNEL);
    ptr->a = 118;
    ptr->b = 212;

    printk(KERN_INFO "Before Free:");
    print(ptr);
    kfree(ptr);
}

void cause_nullderef(void) {
	ptr = kmalloc(sizeof(ABC), GFP_KERNEL);
	ptr -> a = 118;
	ptr -> b = 212;
	printk(KERN_INFO "Before Free");
	print(ptr);
	kfree(ptr);
	ptr = NULL;
	print(ptr);
}

static int __init custom_init(void) {
	cause_nullderef();
	return 1;
}

static void __exit custom_exit(void) {
    printk(KERN_INFO "After Free:");
    print(ptr);
    printk(KERN_INFO "Goodbye |:>)\n\n");
}

module_init(custom_init);
module_exit(custom_exit);


