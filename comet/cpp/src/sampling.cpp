// Implement bounded sampling worker ownership and queue draining.
#include "sampling.hpp"

#include <utility>

namespace comet::detail {
std::shared_ptr<Sampling> Sampling::open() {
    auto result = std::make_shared<Sampling>(); // Workers own only the queue, not the thread manager or idle Client.
    for (auto& thread : result->threads_) {
        ++result->queue_->workers;
        try {
            thread = std::thread([queue = result->queue_] { run(*queue); });
        } catch (...) {
            --result->queue_->workers;
            throw; // result destruction closes and awaits workers already created.
        }
    }
    return result;
}

Sampling::~Sampling() {
    close();
    wait();
}

void Sampling::wait() {
    const std::lock_guard lock(join_); // Multiple application waiters must not join the same thread concurrently.
    for (auto& thread : threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

bool Sampling::submit(Work work) {
    const std::lock_guard lock(queue_->mutex);
    if (queue_->closed || queue_->count == queue_->items.size()) {
        return false;
    }
    queue_->items[(queue_->head + queue_->count) % queue_->items.size()] = std::move(work);
    ++queue_->count;
    queue_->ready.notify_one();
    return true;
}

void Sampling::close() noexcept {
    const std::lock_guard lock(queue_->mutex);
    queue_->closed = true;
    queue_->ready.notify_all();
}

void Sampling::run(Queue& queue) {
    for (;;) {
        Work work; // Release the task and its Beacon/Core ownership at each round's end.
        {
            std::unique_lock lock(queue.mutex);
            queue.ready.wait(lock, [&] { return queue.closed || queue.count; });
            if (!queue.count) {
                break;
            }
            work = std::move(queue.items[queue.head]);
            queue.head = (queue.head + 1) % queue.items.size();
            --queue.count;
        }
        work(); // Beacon catches business exceptions and always returns sampling responsibility.
    }
    queue.workers.fetch_sub(1, std::memory_order_release);
}
} // namespace comet::detail
