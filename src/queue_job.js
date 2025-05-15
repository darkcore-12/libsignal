'use strict';

const _queueAsyncBuckets = new Map();
const _gcLimit = 10000;

/**
 * Ejecuta todas las tareas asíncronas en una cola.
 */
async function _asyncQueueExecutor(queue, cleanup) {
    let offset = 0;

    async function execute() {
        const limit = Math.min(queue.length, _gcLimit);

        for (let i = offset; i < limit; i++) {
            const job = queue[i];
            try {
                const result = await job.awaitable();
                job.resolve(result);
            } catch (error) {
                job.reject(error);
            }
        }

        if (limit < queue.length) {
            // Limpiar tareas procesadas si se llegó al límite
            if (limit >= _gcLimit) {
                queue.splice(0, limit);
                offset = 0;
            } else {
                offset = limit;
            }

            return execute(); // Continuar con lo que queda
        } else {
            cleanup(); // Cola terminada
        }
    }

    try {
        await execute();
    } catch (e) {
        console.error("Error en ejecución de la cola async:", e);
        cleanup();
    }
}

/**
 * Cola de ejecución asincrónica por 'bucket'.
 * Garantiza que las tareas de un mismo bucket se ejecuten en orden.
 */
module.exports = function queueJob(bucket, awaitable) {
    if (typeof awaitable !== 'function') {
        throw new TypeError('awaitable debe ser una función async');
    }

    // Etiquetar la tarea (opcional pero útil para depurar)
    if (!awaitable.name) {
        Object.defineProperty(awaitable, 'name', { writable: true });
        if (typeof bucket === 'string') {
            awaitable.name = bucket;
        }
    }

    let isNewQueue = false;

    if (!_queueAsyncBuckets.has(bucket)) {
        _queueAsyncBuckets.set(bucket, []);
        isNewQueue = true;
    }

    const queue = _queueAsyncBuckets.get(bucket);

    const job = new Promise((resolve, reject) => {
        queue.push({ awaitable, resolve, reject });
    });

    if (isNewQueue) {
        _asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket));
    }

    return job;
};
