/******************************************************************************
    Copyright (c) __20xx __Client_Name. All rights reserved.
    Developed for __Client_Name by Carbon Design Group.
******************************************************************************/

/// @file __TemplateSingletonClass.cpp
/// __One_line_description_of_file.
///
/// __Detailed_description_of_file.


//=============================== INCLUDES ====================================
#include "carbon.h"
#include "__ClassName.h"

namespace __NAMESPACE_NAME
{

    //=================== CONSTANTS, MACROS, AND TYPES ========================

    //============================ VARIABLES ==================================

    /// Pointer to the one-and-only instance of the class.
    __ClassName* __ClassName::_pInstance = 0;
    

    //====================== CLASS MEMBER FUNCTIONS ===========================

    //-------------------------------------------------------------------------
    /// Get singleton instance.
    ///
    /// NOTE: The first time this function is called there should either
    /// be only one thread of execution or the function must be called
    /// within a synchronization mechanism whereby only one thread is
    /// allowed to call at a time.  
    ///
    /// @return One-and-only instance of the __ClassName.
    //-------------------------------------------------------------------------
    __ClassName& 
    __ClassName::GetInstance() { 

        /// Create instance on first demand.
        if (!_pInstance) {
            _pInstance = new __ClassName();
            ASSERT(_pInstance);
        }

        return *_pInstance; 
    }


    //-------------------------------------------------------------------------
    /// Construct a __ClassName.
    ///
    /// __Detailed_description.
    //-------------------------------------------------------------------------
    __ClassName::__ClassName()
        :
        BASE_OF___ClassName(),
        __Other_member_initializers
    {
        ASSERT(__Validate_incoming_parameters);
    }


    //-------------------------------------------------------------------------
    /// Destruct a __ClassName.
    ///
    /// __Detailed_description.
    //-------------------------------------------------------------------------
    __ClassName::~__ClassName()
    {
        // Remember to DELETE() or DELETE_PTR() if needed.
    }


    //-------------------------------------------------------------------------
    /// __One_line_summary_of_function
    ///
    /// __Detailed_description.
    ///
    /// @return __Describe_return_value
    //-------------------------------------------------------------------------
    __TYPE
    __ClassName::__MemberFunction(
        __TYPE __PARAM1, ///< __Description_of_param
        __TYPE __PARAM2  ///< __Description_of_param
    )
    {
        ASSERT(__Validate_incoming_parameters);
    }


} // end __NAMESPACE_NAME

