# API usage guide
This API was developed to provide a native Python integration with all EDL features.

## API setup
Before anything, you should import it and instance the API with:

```python
from edlclient.Library.api import *

e = edl_api()
```

After that, you should set your desired EDL options (those who starts with `--`), e.g. `--debugmode`. For this, you should use the `set_arg()` method, like this:

```python
e.set_arg("--debugmode", True)
```

Be aware that, by default, the `set_arg()` method returns the full arguments dictionary, but, if the passed option doesn't exist, it'll return `Invalid key!`. This should be useful to avoid future errors.

Also, you can use the `reset_arg()` method to set back any option to its default value. This method's return is the same as the `set_arg()`, because it's actually just a wrapper to `set_arg(key, None, True)`.

That said, now you should initialize the API with the `init()` method. However, note that:

1. The API initialization should be done after you set the `--` options

2. To change any `--` option **after** the API initialization, you should reinitialize the API with the `reinit()` method (which is equivalent to `deinit()` + `init()`)

3. You can use the `deinit()` method to "free" the API. This will happen automatically when the API instance (i.e. the Python object) gets destroyed or the program exits

4. Every `init()`/`reinit()`/`deinit()` calls will return the API `status` attribute, which stores a code that can be useful to check if any errors occurred. The stored value will be 1 for error or 0 for success

And, finally, the API is ready to be used!

## EDL commands
In summary, **all EDL commands are API methods** and they follow this same structure: `command([arg1[, arg2[, arg3]]])`. To a better understanding, we're going to take the `peek` command as an example: we know that `peek` requires `<offset>`, `<length>` and `<filename>` as its arguments, respectively. This way, considering the `<offset>` as `0x100000`, `<length>` as `80` and `<filename>` as `output.bin`, we should have this API call:

```python
e.peek(0x100000, 80, "output.bin")
```

And that's it for all the EDL commands! Simple, isn't it?

> For the full command list and their arguments, refer to EDL's documentation (i.e. `edl --help` or `README.md`)

## Basic usage example
This example covers the basic (and probably most common) API usage, so check it out:

```python
from edlclient.Library.api import *

# Step 1
e = edl_api()
e.set_arg("--debugmode", True)
if (e.init() == 1):
	exit(1)

# Step 2
e.peek(0x100000, 80, "peek1.bin")

# Step 3
e.reset_arg("--debugmode")
if (e.reinit() == 1):
	exit(1)

# Step 4
e.peek(0x100080, 80, "peek2.bin")

# Step 5
e.reset()
```

Steps explanation:

1. The API is instanced and initialized with the `--debugmode` option enabled

2. A `peek` command is executed

3. The `--debugmode` option is disabled and, in order to take effect, the API is reinitialized

4. Another `peek` command is executed

5. The Android device is restarted with the `reset` command

For a more contextualized and robust example, check the `Examples/api_example.py`
