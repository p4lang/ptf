class Container(list):
    """Container class to contain protocols"""

    fields = []
    count_field_with_values = 0

    def __init__(self, template, **kwargs):
        super(Container, self).__init__()
        self.params = []
        self.template = template

        names = []
        for field in self.fields:
            if field == "options":
                # DHCP uses a list of tuples for "options" values. Skip
                continue
            values = kwargs.get(field)
            if isinstance(values, (tuple, list)):
                names.append(field)

        # support at most 1 field with multiple values
        if len(names) > 1:
            raise ValueError("Only support at most 1 field with multi values")
        if len(names) == 1:
            Container.count_field_with_values += 1
            name = names[0]
            values = kwargs.get(name)
            for value in values:
                copy = kwargs.copy()
                copy.update({name: value})
                self.params.append(copy)
                self.append(template(**copy))
        else:
            self.params.append(kwargs)
            self.append(template(**kwargs))

        # Check all protocol layers
        # if Container.count_field_with_values > 1:
        #     raise ValueError("Only support at most 1 field with multi values")

    @property
    def name(self):
        return self.__class__.__name__

    def clone(self, index):
        """Clone to a new object using parameter at index"""
        return self.template(**self.params[index])

    def clear(self):
        """Remove all items"""
        while self:
            self.pop()

    def count_layers(self):
        """Return how many protocol layers existed"""
        count = 0
        inner = self[0]
        while hasattr(inner, "name"):
            count += 1
            inner = inner.body
        return count
