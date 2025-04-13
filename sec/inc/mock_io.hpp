#pragma once

#include "minitype.hpp"

enum class IoLogic : u8 {
    low = 0,
    high = 1,
};

constexpr IoLogic operator!(IoLogic logic) {
    return static_cast<IoLogic>(logic == IoLogic::low);
}
using IoActiveLogic = IoLogic;

class MockIo {
protected:
    MockIo() noexcept = default;
    ~MockIo() noexcept = default;
    MockIo(const MockIo&) = default;

    void setIoActivate() const {
        state_ = true;
    }

    void setIoDeactivate() const {
        state_ = false;
    }

    bool getIoState() const {
        return state_;
    }

    void checkIoState() const {
        if (!state_) {
            throwException();
        }
    }
private:
    mutable bool state_ {};

    MockIo& operator=(const MockIo&) = delete;
    MockIo(MockIo&&) = delete;
    MockIo& operator=(MockIo&&) = delete;

    virtual void throwException() const = 0;
};