//
// Created by Zikai Liu on 4/2/22.
//

#ifndef AOS_TEST_PAGING_H
#define AOS_TEST_PAGING_H

#include <mm/mm.h>
#include <aos/paging.h>

void grading_test_paging(struct mm *mm, struct paging_state *st);
void grading_test_fixed_map_more_time(struct mm *mm, struct paging_state *st, int count);
void grading_test_dynamic_map_more_time(struct mm *mm, struct paging_state *st, int count);

#endif  // AOS_TEST_PAGING_H
