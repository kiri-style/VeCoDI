/**
  ******************************************************************************
  * @file    stm32l5xx_hal_secure_sram.h
  * @author  MCD Application Team
  * @brief   Header file of Secure SRAM HAL module.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2019 STMicroelectronics.
  * All rights reserved.</center></h2>
  *
  * This software component is licensed by ST under BSD 3-Clause license,
  * the "License"; You may not use this file except in compliance with the
  * License. You may obtain a copy of the License at:
  *                       opensource.org/licenses/BSD-3-Clause
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STM32L5xx_HAL_SECURE_SRAM_H
#define STM32L5xx_HAL_SECURE_SRAM_H

#ifdef __cplusplus
 extern "C" {
#endif

/* Includes ------------------------------------------------------------------*/
#include "stm32l5xx_hal_def.h"

#if defined (GTZC_SRAM)

/** @addtogroup STM32L5xx_HAL_Driver
  * @{
  */

/** @addtogroup SECURE_SRAM
  * @{
  */

/* Exported types ------------------------------------------------------------*/
/** @defgroup SECURE_SRAM_Exported_Types Secure SRAM Exported Types
  * @{
  */

/**
  * @brief  HAL Secure SRAM State structures definition
  */
typedef enum
{
  HAL_SECURE_SRAM_STATE_RESET     = 0x00U,  /*!< Secure SRAM not yet initialized or disabled */
  HAL_SECURE_SRAM_STATE_READY     = 0x01U,  /*!< Secure SRAM initialized and ready for use   */
  HAL_SECURE_SRAM_STATE_BUSY      = 0x02U,  /*!< Secure SRAM internal process is ongoing     */
  HAL_SECURE_SRAM_STATE_ERROR     = 0x03U,  /*!< Secure SRAM error state                     */
  HAL_SECURE_SRAM_STATE_PROTECTED = 0x04U   /*!< Secure SRAM device write protected          */
} HAL_SECURE_SRAM_StateTypeDef;

/**
  * @brief  Secure SRAM handle Structure definition
  */
#if (USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS == 1)
typedef struct __SECURE_SRAM_HandleTypeDef
#else
typedef struct
#endif /* USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS */
{
  GTZC_SRAM_TypeDef              *Instance;  /*!< Register base address                */
  GTZC_SRAM_InitTypeDef          Init;       /*!< Secure SRAM configuration parameters */
  HAL_LockTypeDef                Lock;       /*!< Secure SRAM locking object           */
  __IO HAL_SECURE_SRAM_StateTypeDef State;   /*!< Secure SRAM device access state      */

#if (USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS == 1)
  void (* MspInitCallback)(struct __SECURE_SRAM_HandleTypeDef *hsram);    /*!< Secure SRAM Msp Init callback   */
  void (* MspDeInitCallback)(struct __SECURE_SRAM_HandleTypeDef *hsram);  /*!< Secure SRAM Msp DeInit callback */
#endif
} SECURE_SRAM_HandleTypeDef;

#if (USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS == 1)
/**
  * @brief  HAL Secure SRAM Callback ID enumeration definition
  */
typedef enum
{
  HAL_SECURE_SRAM_MSP_INIT_CB_ID       = 0x00U,  /*!< Secure SRAM MspInit Callback ID   */
  HAL_SECURE_SRAM_MSP_DEINIT_CB_ID     = 0x01U   /*!< Secure SRAM MspDeInit Callback ID */
} HAL_SECURE_SRAM_CallbackIDTypeDef;

/**
  * @brief  HAL Secure SRAM Callback pointer definition
  */
typedef void (*pSECURE_SRAM_CallbackTypeDef)(SECURE_SRAM_HandleTypeDef *hsram);
#endif

/**
  * @}
  */

/* Exported constants --------------------------------------------------------*/
/** @defgroup SECURE_SRAM_Exported_Constants Secure SRAM Exported Constants
  * @{
  */

/** @defgroup SECURE_SRAM_Configuration Secure SRAM Configuration
  * @{
  */
#define SECURE_SRAM_CONFIG_DEFAULT              0x00000000U
#define SECURE_SRAM_CONFIG_SECURE               GTZC_TZSC_ATTRIBUTE_SECURE
#define SECURE_SRAM_CONFIG_NONSECURE            GTZC_TZSC_ATTRIBUTE_NSEC
#define SECURE_SRAM_CONFIG_PRIVILEGED_ONLY      GTZC_TZSC_ATTRIBUTE_PRIV
#define SECURE_SRAM_CONFIG_LOCK                 GTZC_TZSC_ATTRIBUTE_LOCK
/**
  * @}
  */

/** @defgroup SECURE_SRAM_Area Secure SRAM Area
  * @{
  */
#define SECURE_SRAM_AREA_SRAM1                  GTZC_TZSC_PERIPH_SRAM1
#define SECURE_SRAM_AREA_SRAM2                  GTZC_TZSC_PERIPH_SRAM2
#define SECURE_SRAM_AREA_SRAM3                  GTZC_TZSC_PERIPH_SRAM3
#define SECURE_SRAM_AREA_ALL                    (SECURE_SRAM_AREA_SRAM1 | \
                                                 SECURE_SRAM_AREA_SRAM2 | \
                                                 SECURE_SRAM_AREA_SRAM3)
/**
  * @}
  */

/**
  * @}
  */

/* Exported macros -----------------------------------------------------------*/
/** @defgroup SECURE_SRAM_Exported_Macros Secure SRAM Exported Macros
  * @{
  */

/** @brief Reset Secure SRAM handle state.
  * @param  __HANDLE__ Secure SRAM handle
  * @retval None
  */
#if (USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS == 1)
#define __HAL_SECURE_SRAM_RESET_HANDLE_STATE(__HANDLE__)         do {                                             \
                                                                       (__HANDLE__)->State = HAL_SECURE_SRAM_STATE_RESET; \
                                                                       (__HANDLE__)->MspInitCallback = NULL;       \
                                                                       (__HANDLE__)->MspDeInitCallback = NULL;     \
                                                                     } while(0)
#else
#define __HAL_SECURE_SRAM_RESET_HANDLE_STATE(__HANDLE__) ((__HANDLE__)->State = HAL_SECURE_SRAM_STATE_RESET)
#endif

/**
  * @}
  */

/* Exported functions --------------------------------------------------------*/
/** @addtogroup SECURE_SRAM_Exported_Functions Secure SRAM Exported Functions
  * @{
  */

/** @addtogroup SECURE_SRAM_Exported_Functions_Group1 Initialization and de-initialization functions
  * @{
  */
/* Initialization/de-initialization functions  ********************************/
HAL_StatusTypeDef HAL_SECURE_SRAM_Init(SECURE_SRAM_HandleTypeDef *hsram);
HAL_StatusTypeDef HAL_SECURE_SRAM_DeInit(SECURE_SRAM_HandleTypeDef *hsram);
void HAL_SECURE_SRAM_MspInit(SECURE_SRAM_HandleTypeDef *hsram);
void HAL_SECURE_SRAM_MspDeInit(SECURE_SRAM_HandleTypeDef *hsram);
/**
  * @}
  */

/** @addtogroup SECURE_SRAM_Exported_Functions_Group2 Configuration functions
  * @{
  */
/* Configuration functions  ***************************************************/
HAL_StatusTypeDef HAL_SECURE_SRAM_ConfigArea(SECURE_SRAM_HandleTypeDef *hsram, uint32_t Area, uint32_t Configuration);
HAL_StatusTypeDef HAL_SECURE_SRAM_EnableArea(SECURE_SRAM_HandleTypeDef *hsram, uint32_t Area);
HAL_StatusTypeDef HAL_SECURE_SRAM_DisableArea(SECURE_SRAM_HandleTypeDef *hsram, uint32_t Area);
HAL_StatusTypeDef HAL_SECURE_SRAM_LockArea(SECURE_SRAM_HandleTypeDef *hsram, uint32_t Area);
/**
  * @}
  */

/** @addtogroup SECURE_SRAM_Exported_Functions_Group3 State functions
  * @{
  */
/* Secure SRAM State functions ************************************************/
HAL_SECURE_SRAM_StateTypeDef HAL_SECURE_SRAM_GetState(SECURE_SRAM_HandleTypeDef *hsram);
/**
  * @}
  */

#if (USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS == 1)
/** @addtogroup SECURE_SRAM_Exported_Functions_Group4 Callback functions
  * @{
  */
/* Secure SRAM Callback registering/unregistering *****************************/
HAL_StatusTypeDef HAL_SECURE_SRAM_RegisterCallback(SECURE_SRAM_HandleTypeDef *hsram, 
                                                   HAL_SECURE_SRAM_CallbackIDTypeDef CallbackId, 
                                                   pSECURE_SRAM_CallbackTypeDef pCallback);
HAL_StatusTypeDef HAL_SECURE_SRAM_UnRegisterCallback(SECURE_SRAM_HandleTypeDef *hsram, 
                                                     HAL_SECURE_SRAM_CallbackIDTypeDef CallbackId);
/**
  * @}
  */
#endif /* USE_HAL_SECURE_SRAM_REGISTER_CALLBACKS */

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

#endif /* GTZC_SRAM */

#ifdef __cplusplus
}
#endif

#endif /* STM32L5xx_HAL_SECURE_SRAM_H */
