#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/printk.h>

#include "ns_irq.h"

// Assure que le linker voit la fonction C++ comme C
#ifdef __cplusplus
extern "C" {
#endif
#include "inference.h"
#ifdef __cplusplus
}
#endif

#define INFERENCE_GPIO_NODE DT_ALIAS(sw0)

static const struct gpio_dt_spec inference_gpio =
    GPIO_DT_SPEC_GET(INFERENCE_GPIO_NODE, gpios);

static struct gpio_callback inference_cb;

static void inference_gpio_isr(const struct device *dev,
                               struct gpio_callback *cb,
                               uint32_t pins)
{
    ARG_UNUSED(dev);
    ARG_UNUSED(cb);
    ARG_UNUSED(pins);

    printk("[NS GPIO IRQ] Trigger inference\n");
    printk("[NS GPIO IRQ] user mode = %d\n", k_is_user_context());

    // Demande au secure world de lancer l’inférence
    printk("[NS GPIO IRQ] Calling run_cifar_inference()\n");
    run_cifar_inference();
    printk("[NS GPIO IRQ] Inference finished\n");
}

void ns_irq_init(void)
{
     printk("[IRQ] GPIO IRQ fired | user mode = %d\n", k_is_user_context());
    if (!device_is_ready(inference_gpio.port)) {
        printk("GPIO not ready\n");
        return;
    }

    gpio_pin_configure_dt(&inference_gpio, GPIO_INPUT);
    gpio_pin_interrupt_configure_dt(&inference_gpio,
                                    GPIO_INT_EDGE_TO_ACTIVE);

    gpio_init_callback(&inference_cb,
                       inference_gpio_isr,
                       BIT(inference_gpio.pin));

    gpio_add_callback(inference_gpio.port, &inference_cb);

    printk("[NS GPIO IRQ] Initialized\n");
}