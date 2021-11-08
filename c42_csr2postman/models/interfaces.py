from enum import Enum


#
# This code was taken from:
#   https://gist.github.com/cr0hn/89172938b7ac42c3100f4980ad881a24
#
class Serializable:

    def _clean_dict_(self,
                   data = None,
                   clean_or_raw: str = "clean") -> dict:

        # DICT
        if type(data) is dict:
            ret = {}

            for x, y in data.items():

                if x.startswith("raw") and clean_or_raw == "clean":
                    continue

                ret[x] = self._clean_dict_(y, clean_or_raw=clean_or_raw)

            return ret

        # LIST
        elif type(data) is list:

            ret = []

            for d in data:
                ret.append(self._clean_dict_(d, clean_or_raw=clean_or_raw))

            return ret

        elif hasattr(data, "clean_dict"):
            return data.clean_dict(clean_or_raw=clean_or_raw)

        elif isinstance(data, Enum):
            return data.value

        else:
            if hasattr(data, "decode"):
                return data.decode()

            return data

    def clean_dict(self,
                   clean_or_raw: str = "clean") -> dict:
        """removes fields 'raw' from content"""

        return self._clean_dict_(self.__dict__, clean_or_raw=clean_or_raw)


    def raw_dict(self) -> dict:
        """Dumps all content to valid json file"""
        return self.clean_dict(clean_or_raw="raw")
