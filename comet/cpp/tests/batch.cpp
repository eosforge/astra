// Own bounded resident mesh workers and drain every admitted callback before releasing its inputs.
#include "batch.hpp"

#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <utility>

namespace comet::test {
Batch::Batch(std::size_t count) {

    if (count == 0 || count > 96) {
        throw std::invalid_argument("Invalid mesh worker count");
    }
    workers_.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        workers_.emplace_back([this, index](std::stop_token stop) { work(stop, index); });
    }
}

void Batch::run(std::function<void(std::size_t)> task) {

    std::unique_lock lock(mutex_);
    if (active_ || !task) {
        throw std::logic_error("Invalid mesh batch admission");
    }
    task_ = std::move(task);
    failure_ = nullptr;
    active_ = true;
    pending_ = workers_.size();
    generation_ = !generation_;
    ready_.notify_all();
    if (!done_.wait_for(lock, std::chrono::seconds(20), [this] { return pending_ == 0; })) {
        // Returning would destroy inputs still borrowed by callbacks. The outer process owner retains cleanup.
        std::fputs("Mesh batch did not drain within 20 seconds\n", stderr);
        std::terminate();
    }
    task_ = {};
    active_ = false;
    if (failure_) {
        std::rethrow_exception(failure_);
    }
}

void Batch::work(std::stop_token stop, std::size_t index) {

    bool generation = false; // Every worker starts before the first admitted generation.
    std::unique_lock lock(mutex_);
    while (ready_.wait(lock, stop, [this, generation] { return generation_ != generation; })) {
        generation = generation_;
        lock.unlock();
        std::exception_ptr failure; // Only the owning worker writes this local exception.
        try {
            task_(index);
        } catch (...) {
            failure = std::current_exception();
        }
        lock.lock();
        if (failure && !failure_) {
            failure_ = failure;
        }
        if (--pending_ == 0) {
            done_.notify_one();
        }
    }
}
} // namespace comet::test
