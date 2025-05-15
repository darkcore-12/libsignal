'use strict';

const _queueAsyncBuckets = new Map();
const _gcLimit = 10000;

async function _asyncQueueExecutor(queue, cleanup) {
    let offt = 0;

    async function execute() {
        const limit = Math.min(queue.length, _gcLimit);
        for (; offt < limit; offt++) {
            const job = queue[offt];
            try {
                job.resolve(await job.awaitable());
            } catch (e) {
                job.reject(e);
            }
        }
        if (limit < queue.length) {
            // Limpiar memoria si sobrepasa límite
            if (limit >= _gcLimit) {
                queue.splice(0, limit);
                offt = 0;
            }
            execute(); // continuar con el siguiente batch
        } else {
            cleanup(); // terminar y eliminar bucket
        }
    }

    execute();
}

module.exports = function (bucket, awaitable) {
    if (!awaitable.name) {
        // Si la función no tiene nombre, se le asigna el bucket (opcional)
        Object.defineProperty(awaitable, 'name', { writable: true });
        if (typeof bucket === 'string') {
            awaitable.name = bucket;
        }
    }
    let inactive = false;
    if (!_queueAsyncBuckets.has(bucket)) {
        _queueAsyncBuckets.set(bucket, []);
        inactive = true;
    }
    const queue = _queueAsyncBuckets.get(bucket);
    const job = new Promise((resolve, reject) => queue.push({
        awaitable,
        resolve,
        reject
    }));
    if (inactive) {
        _asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket));
    }
    return job;
};
