/**
    @file
    @brief Additional container types.
*/

#ifndef _HOST_PEERING_CONTAINER_H
#define _HOST_PEERING_CONTAINER_H

#include <functional>
#include <queue>
#include <utility>
#include <vector>

/**
    @brief Compare utility for #mapped_priority_queue.
*/
template <
    typename Item,
    typename Priority = typename Item::first_type,
    typename PriorityCompare = std::less<Priority>>
class mapped_priority_queue_compare
{
public:
    mapped_priority_queue_compare()
    :
        mPriorityCompare()
    {
    }

    bool operator()(
        Item const & x,
        Item const & y)
    const
    {
        return mPriorityCompare(x.first, y.first);
    }

protected:
    PriorityCompare mPriorityCompare;
};

/**
    @brief Priority queue with separate priorities and values.
*/
template <
    typename Priority,
    typename Value,
    typename PriorityCompare = std::less<Priority>,
    typename Item = std::pair<Priority, Value>,
    typename Container = std::vector<Item>,
    typename Compare = mapped_priority_queue_compare<Item, Priority, PriorityCompare>>
using mapped_priority_queue = std::priority_queue<Item, Container, Compare>;

#endif
