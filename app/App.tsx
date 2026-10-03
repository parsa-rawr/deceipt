/**
 * The application entry point.
 *
 * Everything real lives in `src/`: the shell (`src/App.tsx`), the two mode
 * screens (`src/ui/`), the checkout state machine (`src/checkout/`), the frozen
 * protocol implementation (`src/protocol/`) and the bridge contract
 * (`src/native/DeceiptNative.ts`). This file only mounts the shell so the
 * registered component path stays the standard React Native one.
 */

import React from 'react';
import App from './src/App';

export default App;
