'use strict';

// Mapa que almacena colas para cada bucket
const _queueAsyncBuckets = new Map();

// Límite máximo para el tamaño del batch antes de limpiar memoria
const _gcLimit = 10000;

/**
 * Ejecuta en serie todas las promesas en la cola de un bucket.
 * @param {Array} queue Array de jobs { awaitable, resolve, reject }
 * @param {Function} cleanup Función para limpiar el bucket cuando termina
 */
async function _asyncQueueExecutor(queue, cleanup) {
  let offt = 0;

  // Función que procesa el queue en batches
  async function execute() {
    const limit = Math.min(queue.length, _gcLimit);

    for (; offt < limit; offt++) {
      const job = queue[offt];
      try {
        // Ejecuta la función awaitable y resuelve la promesa asociada
        const result = await job.awaitable();
        job.resolve(result);
      } catch (e) {
        // Si hay error, rechaza la promesa asociada
        job.reject(e);
      }
    }

    if (limit < queue.length) {
      // Si hay más trabajos después del límite, limpiar memoria y continuar con siguiente batch
      if (limit >= _gcLimit) {
        queue.splice(0, limit);
        offt = 0;
      }
      // Importante: esperar para evitar pila infinita de llamadas recursivas
      await execute();
    } else {
      // Todos los trabajos procesados, limpiar bucket
      cleanup();
    }
  }

  await execute();
}

/**
 * Función principal para encolar funciones async por bucket
 * @param {string} bucket Identificador del bucket (grupo)
 * @param {Function} awaitable Función asíncrona que retorna una promesa
 * @returns {Promise} Promesa que se resuelve con el resultado del awaitable
 */
module.exports = function (bucket, awaitable) {
  // Si la función no tiene nombre, asignarle el bucket para depuración (opcional)
  if (!awaitable.name && typeof bucket === 'string') {
    Object.defineProperty(awaitable, 'name', {
      value: bucket,
      writable: true,
    });
  }

  let isNewBucket = false;

  // Crear cola si no existe para este bucket
  if (!_queueAsyncBuckets.has(bucket)) {
    _queueAsyncBuckets.set(bucket, []);
    isNewBucket = true;
  }

  const queue = _queueAsyncBuckets.get(bucket);

  // Crear una promesa para el trabajo encolado
  const job = new Promise((resolve, reject) => {
    queue.push({
      awaitable,
      resolve,
      reject,
    });
  });

  // Si es un bucket nuevo, iniciar el procesamiento
  if (isNewBucket) {
    // No await para no bloquear la función
    _asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket))
      .catch((err) => {
        // Aquí se podría loggear un error si ocurre en la ejecución del queue
        console.error('Error in async queue executor:', err);
      });
  }

  return job;
};
