#!/bin/bash
echo "=== Vérification des fichiers de classification d'image ==="
echo

echo "1. test_images_simple.h :"
if [ -f src/test_images_simple.h ]; then
    echo "   ✓ Présent"
    echo "   Premières lignes :"
    head -5 src/test_images_simple.h
else
    echo "   ✗ Manquant"
fi
echo

echo "2. test_images_simple.c :"
if [ -f src/test_images_simple.c ]; then
    echo "   ✓ Présent"
    echo "   Taille : $(wc -l < src/test_images_simple.c) lignes"
else
    echo "   ✗ Manquant"
fi
echo

echo "3. image_classifier.c :"
if [ -f src/image_classifier.c ]; then
    echo "   ✓ Présent"
    echo "   Taille : $(wc -l < src/image_classifier.c) lignes"
else
    echo "   ✗ Manquant - Création..."
    # Créer le fichier s'il manque
    cat > src/image_classifier.c << 'END'
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include "test_images_simple.h"

static const char* get_class_name(uint8_t class_id) {
    const char* names[] = {
        "avion", "voiture", "oiseau", "chat", "cerf",
        "chien", "grenouille", "cheval", "bateau", "camion"
    };
    return (class_id < 10) ? names[class_id] : "inconnu";
}

void run_image_classification_test(void) {
    printk("\n=== Image Classification Test ===\n");
    
    for (int i = 0; i < NUM_SIMPLE_IMAGES; i++) {
        printk("Image %d: Label = %s\n", i, get_class_name(simple_test_labels[i]));
        k_msleep(100);
    }
    
    printk("=== Test completed ===\n");
}
END
    echo "   ✓ Fichier créé"
fi
echo

echo "4. model.h et model.cc :"
if [ -f src/model.h ] && [ -f src/model.cc ]; then
    echo "   ✓ Présents"
    echo "   Taille modèle : $(grep -o 'g_model_len = [0-9]*' src/model.cc | grep -o '[0-9]*') bytes"
else
    echo "   ⚠ Partiellement présent"
fi
echo

echo "=== Vérification terminée ==="
